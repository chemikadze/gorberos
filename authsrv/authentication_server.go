package authsrv

import (
	"errors"
	"github.com/chemikadze/gorberos/crypto"
	"github.com/chemikadze/gorberos/database"
	"github.com/chemikadze/gorberos/datamodel"
	"math"
	"time"
)

type KdcServer interface {
	AuthenticationServerExchange(datamodel.AS_REQ) (ok bool, err datamodel.KRB_ERROR, rep datamodel.AS_REP)
	TgsExchange(datamodel.TGS_REQ) (ok bool, err datamodel.KRB_ERROR, rep datamodel.TGS_REP)
	RevokeTickets(starTime, endTime datamodel.KerberosTime)
}

const (
	ONE_DAY = int64(24 * 60 * 60)
)

func NewKdcServer(realm datamodel.Realm, database database.KdcDatabase, crypto crypto.Factory) KdcServer {
	maxLifetime := ONE_DAY
	return &authenticationServer{
		realm:             realm,
		serializer:        datamodel.NewSerializer(),
		database:          database,
		crypto:            crypto,
		maxExpirationTime: maxLifetime,
		maxPostdate:       ONE_DAY,
		maxRenewTime:      ONE_DAY,
		revocationHotlist: NewRevocationHotlist(maxLifetime),
	}
}

type authenticationServer struct {
	database          database.KdcDatabase
	crypto            crypto.Factory
	serializer		  datamodel.Serializer
	clockSkew         int64
	minTicketLifetime int64
	maxRenewTime      int64
	realm             datamodel.Realm
	maxPostdate       int64
	maxExpirationTime int64
	tgsPrinc          datamodel.PrincipalName
	revocationHotlist RevocationHotlist
}

func (a *authenticationServer) RevokeTickets(starTime, endTime datamodel.KerberosTime) {
	a.revocationHotlist.Revoke(starTime, endTime)
}

func (a *authenticationServer) AuthenticationServerExchange(req datamodel.AS_REQ) (ok bool, err datamodel.KRB_ERROR, rep datamodel.AS_REP) {
	// initial integrity verification
	if req.Req_body.Sname.IsEmpty() || req.Req_body.Cname.IsEmpty() {
		err := newAsError(req)
		err.Error_code = 42
		err.E_text = "Sname or Cname missing in request body"
		return false, err, noRep()
	}
	sname := req.Req_body.Sname

	cname := req.Req_body.Cname
	// get principal info from database
	clientPrinc, ok := a.database.GetPrincipal(cname)
	if !ok {
		return false, newAsErrorFromReq(req, datamodel.KDC_ERR_C_PRINCIPAL_UNKNOWN), noRep()
	}
	serverPrinc, ok := a.database.GetPrincipal(sname)
	if !ok {
		return false, newAsErrorFromReq(req, datamodel.KDC_ERR_S_PRINCIPAL_UNKNOWN), noRep()
	}

	// run preauth checks
	if ok, err := a.preauthCheck(req); !ok {
		return false, err, noRep()
	}

	// find best encryption algorithm and keys
	if !a.checkEtypes(req.Req_body.Etype) {
		return false, algorithmNotFoundError(req), noRep()
	}
	ok, clientKey := a.getSupportedKey(req.Req_body.Etype, clientPrinc.SecretKeys)
	sessionAlgo := a.selectSessionKeyAlgo(req.Req_body.Etype)
	sessionKey := sessionAlgo.GenerateKey()
	// TODO support POSTDATE
	err, startTime, invalid := a.getStarttime(req)
	if err.Error_code != datamodel.KDC_ERR_NONE {
		return false, err, noRep()
	}
	expirationTime := getTgtExpirationTime(
		a.maxExpirationTime, clientPrinc.MaxExpirationTime,
		datamodel.KerberosTime(startTime),
		datamodel.KerberosTime(req.Req_body.Till))
	if ok, err := a.checkMinLifetime(datamodel.KDC_REQ(req), startTime, expirationTime); !ok {
		return false, err, noRep()
	}
	kdcFlags := datamodel.KDCOptions(req.Req_body.Kdc_options)
	renewable := kdcFlags.Get(datamodel.KDC_FLAG_RENEWABLE_OK)
	var renewTill datamodel.KerberosTime
	if renewable {
		renewTill = a.calcNextRenewTill(clientPrinc, serverPrinc, datamodel.KerberosTime(req.Req_body.Rtime))
	}

	// update lr info
	authTime, _ := kerberosNow()
	a.database.UpdateLastReq(cname, datamodel.LR_TYPE_ANY, authTime)
	a.database.UpdateLastReq(cname, datamodel.LR_TYPE_INITIAL_REQUEST, authTime)

	// set ticket flags
	flags := datamodel.NewTicketFlags()
	flags.Set(datamodel.TKT_FLAG_FORWARDABLE, kdcFlags.Get(datamodel.KDC_FLAG_FORWARDABLE))
	flags.Set(datamodel.TKT_FLAG_MAY_POSTDATE, kdcFlags.Get(datamodel.KDC_FLAG_ALLOW_POSTDATE))
	flags.Set(datamodel.TKT_FLAG_POSTDATED, kdcFlags.Get(datamodel.KDC_FLAG_POSTDATED))
	flags.Set(datamodel.TKT_FLAG_PROXIABLE, kdcFlags.Get(datamodel.KDC_FLAG_PROXIABLE))
	flags.Set(datamodel.TKT_FLAG_RENEWABLE, kdcFlags.Get(datamodel.KDC_FLAG_RENEWABLE))
	flags.Set(datamodel.TKT_FLAG_INVALID, invalid)
	flags.Set(datamodel.TKT_FLAG_INITIAL, true)

	// fill ticket info
	encTicket := datamodel.EncTicketPart{
		Flags:  flags.ToWire(),
		Key:    sessionKey,
		Crealm: req.Req_body.Realm,
		Cname:  cname,
		//Transited         TransitedEncoding
		Authtime:  authTime.ToWire(),
		Starttime: startTime.ToWire(),
		Endtime:   expirationTime.ToWire(),
		Renew_till: renewTill.ToWire(),
		Caddr:     req.Req_body.Addresses,
		//AuthorizationData AuthorizationData
	}
	ticket := datamodel.Ticket{
		Realm:   a.realm,
		Sname:   sname,
		Enc_part: a.encryptTicketPart(serverPrinc.SecretKeys, encTicket),
	}
	encAsRep := datamodel.EncASRepPart{
		Key:           sessionKey,
		Last_req:       clientPrinc.LastReq,
		Nonce:         req.Req_body.Nonce,
		Key_expiration: keyExpirationFromLastReq(clientPrinc.LastReq).ToWire(),
		Flags:         flags.ToWire(),
		Authtime:      authTime.ToWire(),
		Starttime:     startTime.ToWire(),
		Endtime:       expirationTime.ToWire(),
		Renew_till:     renewTill.ToWire(),
		Srealm:        a.realm,
		Sname:         sname,
		Caddr:         req.Req_body.Addresses,
	}
	rep = datamodel.AS_REP{
		Padata:  make([]datamodel.PA_DATA, 0), // TODO
		Crealm:  req.Req_body.Realm,
		Cname:   cname,
		Ticket:  ticket,
		Enc_part: a.encryptAsRepPart(clientKey, encAsRep),
	}
	return true, noError(), rep
}

func newAsErrorFromReq(req datamodel.AS_REQ, code int32) datamodel.KRB_ERROR {
	return newErrorFromReq(datamodel.KDC_REQ(req), code)
}

func newTgsErrorFromReq(req datamodel.TGS_REQ, code int32) datamodel.KRB_ERROR {
	return newErrorFromReq(datamodel.KDC_REQ(req), code)
}

func newErrorFromReq(req datamodel.KDC_REQ, code int32) datamodel.KRB_ERROR {
	ctime := time.Now()
	return datamodel.KRB_ERROR{
		Ctime:     datamodel.KerberosTimeFromUnix(ctime.Unix()).ToWire(),
		Cusec:     datamodel.Microseconds(ctime.Nanosecond() / 1000),
		Error_code: datamodel.Int32(code),
		//Cname: *req.Req_body.Cname,
		Crealm: req.Req_body.Realm,
		//Sname:     *req.Req_body.Sname,
		E_data: make([]byte, 0),
	}
}

func (a *authenticationServer) checkEtypes(etypes []datamodel.Int32) bool {
	for _, requested := range etypes {
		if isSupportedEtype(a.crypto, requested) {
			return true
		}
	}
	return false
}

func (a *authenticationServer) getSupportedKey(algo []datamodel.Int32, clientKeys []datamodel.EncryptionKey) (bool, datamodel.EncryptionKey) {
	for _, requested := range algo {
		if !isSupportedEtype(a.crypto, requested) {
			continue
		}
		for _, key := range clientKeys {
			if key.Keytype == requested {
				return true, key
			}
		}
	}
	return false, datamodel.EncryptionKey{}
}

func (a *authenticationServer) selectSessionKeyAlgo(algo []datamodel.Int32) crypto.Algorithm {
	for _, requested := range algo {
		if isSupportedEtype(a.crypto, requested) {
			return a.crypto.Create(requested)
		}
	}
	panic("not found supported algorithm")
}

func isSupportedEtype(factory crypto.EncryptionFactory, requested datamodel.Int32) bool {
	for _, supported := range factory.SupportedETypes() {
		if supported == requested {
			return true
		}
	}
	return false
}

func algorithmNotFoundError(req datamodel.AS_REQ) datamodel.KRB_ERROR {
	now := time.Now()
	return datamodel.KRB_ERROR{
		Ctime:     datamodel.KerberosTimeNow().ToWire(),
		Cusec:     datamodel.Microseconds(now.Nanosecond() / 1000),
		Error_code: datamodel.KDC_ERR_ETYPE_NOSUPP,
		Crealm:    req.Req_body.Realm,
		Sname:     req.Req_body.Sname,
		E_text:     "Neither of requested encryption types is supported",
	}
}

func (a *authenticationServer) getStarttime(req datamodel.AS_REQ) (err datamodel.KRB_ERROR, t datamodel.KerberosTime, invalid bool) {
	now, _ := kerberosNow()
	if datamodel.KerberosTime(req.Req_body.From).IsEmpty() {
		return noError(), now, false
	}
	difference := req.Req_body.From.Unix() - time.Now().Unix() // -past, +future
	if difference < 0 {
		return noError(), now, false
	}
	postdated := datamodel.KDCOptions(req.Req_body.Kdc_options).Get(datamodel.KDC_FLAG_POSTDATED)
	if postdated && difference < a.clockSkew {
		return noError(), now, false
	}
	if !postdated && difference > a.clockSkew {
		err := newAsError(req)
		err.Error_code = datamodel.KDC_ERR_CANNOT_POSTDATE
		return err, datamodel.KerberosTime{}, false
	}
	// check against policy
	if postdated && difference > a.maxPostdate {
		err := newAsError(req)
		err.Error_code = datamodel.KDC_ERR_CANNOT_POSTDATE
		return err, datamodel.KerberosTime{}, false
	}
	// postdated ticket beyond clock skew clock skew or non-postdated within clock skew
	return noError(), datamodel.KerberosTime(req.Req_body.From), true

}

func getTgtExpirationTime(
	realmExpirationTime int64,
	princExpirationTime int64,
	startTime datamodel.KerberosTime,
	requestedTill datamodel.KerberosTime) datamodel.KerberosTime {

	if requestedTill == datamodel.KerberosEpoch() {
		requestedTill.SetTimestamp(math.MaxInt64)
	}
	maxExpiration := min64(princExpirationTime, realmExpirationTime)
	enforced := min64(requestedTill.ToUnix(), startTime.ToUnix()+maxExpiration)
	return datamodel.KerberosTimeFromUnix(enforced)
}

// TODO
func (a *authenticationServer) preauthCheck(req datamodel.AS_REQ) (ok bool, err datamodel.KRB_ERROR) {
	return true, noError()
}

func newAsError(req datamodel.AS_REQ) datamodel.KRB_ERROR {
	return newKdcError(datamodel.KDC_REQ(req))
}

func newTgsError(req datamodel.TGS_REQ) datamodel.KRB_ERROR {
	return newKdcError(datamodel.KDC_REQ(req))
}

func newKdcError(req datamodel.KDC_REQ) datamodel.KRB_ERROR {
	Ctime, usec := kerberosNow()
	err := datamodel.KRB_ERROR{
		Ctime: Ctime.ToWire(),
		Cusec: datamodel.Microseconds(usec),
		//Error_code: ,
		Crealm: req.Req_body.Realm,
		//E_text:     ,
		//EData:     make([]byte, 0),
	}
	if req.Req_body.Sname.IsEmpty() {
		err.Sname = req.Req_body.Sname
	}
	return err
}

func (a *authenticationServer) checkMinLifetime(req datamodel.KDC_REQ, startTime datamodel.KerberosTime, expirationTime datamodel.KerberosTime) (bool, datamodel.KRB_ERROR) {
	if expirationTime.ToUnix() - startTime.ToUnix() < a.minTicketLifetime {
		err := newKdcError(req)
		err.Error_code = datamodel.KDC_ERR_NEVER_VALID
		return false, err
	} else {
		return true, noError()
	}
}

func (a *authenticationServer) calcNextRenewTill(sprinc database.PrincipalInfo, cprinc database.PrincipalInfo, rtime datamodel.KerberosTime) datamodel.KerberosTime {
	maxRenewTime := min64(min64(sprinc.MaxRenewTime, cprinc.MaxRenewTime), a.maxRenewTime)
	if rtime.IsEmpty() {
		maxRenewTime = min64(maxRenewTime, rtime.ToUnix())
	}
	return datamodel.KerberosTimeFromUnix(maxRenewTime)
}

func (a *authenticationServer) encryptTicketPart(keys []datamodel.EncryptionKey, ticket datamodel.EncTicketPart) datamodel.EncryptedData {
	// TODO picking logic
	key := keys[0]
	algo := a.crypto.Create(datamodel.Int32(key.Keytype))
	err, data := algo.Encrypt(key, ticket)
	if err != nil {
		panic(err) // TODO should never happen
	}
	return data
}

func (a *authenticationServer) encryptAsRepPart(key datamodel.EncryptionKey, encAsRep datamodel.EncASRepPart) datamodel.EncryptedData {
	algo := a.crypto.Create(datamodel.Int32(key.Keytype))
	err, data := algo.Encrypt(key, encAsRep)
	if err != nil {
		panic(err) // TODO should never happen
	}
	return data
}

func min64(a, b int64) int64 {
	if a > b {
		return b
	} else {
		return a
	}
}

func max64(a, b int64) int64 {
	if a < b {
		return b
	} else {
		return a
	}
}


func noError() datamodel.KRB_ERROR {
	return datamodel.KRB_ERROR{}
}

func noRep() datamodel.AS_REP {
	return datamodel.AS_REP{}
}

func kerberosNow() (t datamodel.KerberosTime, usec int32) {
	return datamodel.KerberosTimeNowUsec()
}

func keyExpirationFromLastReq(lastReq datamodel.LastReq) datamodel.KerberosTime {
	minElem := datamodel.KerberosTimeFromUnix(math.MaxInt64)
	for _, elem := range lastReq {
		if elem.Lr_type == datamodel.LR_TYPE_PASSWORD_EXPIRES || elem.Lr_type == datamodel.LR_TYPE_ACCOUNT_EXPIRES {
			if datamodel.KerberosTime(elem.Lr_value).ToUnix() < datamodel.KerberosTime(minElem).ToUnix() {
				minElem.SetTimestamp(datamodel.KerberosTime(elem.Lr_value).ToUnix())
			}
		}
	}
	if minElem.ToUnix() == math.MaxInt64 {
		return datamodel.KerberosTime{}
	} else {
		return minElem
	}
}

//issued on the basis of a TGT (in which case the INITIAL flag is
//clear, but the PRE-AUTHENT and HW-AUTHENT flags are carried forward
//from the TGT).

//validated by the KDC before use, by being presented to the KDC in a
//TGS request with the VALIDATE option specified.  The KDC will only
//validate tickets after their starttime has passed.  The validation is
//required so that postdated tickets that have been stolen before their
//starttime can be rendered permanently invalid (through a hot-list
//mechanism) (see Section 3.3.3.1).

func (a *authenticationServer) TgsExchange(req datamodel.TGS_REQ) (ok bool, kerr datamodel.KRB_ERROR, rep datamodel.TGS_REP) {
	if req.Req_body.Realm != a.realm {
		// appr cross-realm key MUST be used
		return false, datamodel.NewErrorGeneric(a.realm, datamodel.PrincipalName{}, "Cross-realm auth not implemented"), noTgsRep()
	}
	// initial integrity verification
	if req.Req_body.Sname.IsEmpty() {
		err := newTgsError(req)
		err.Error_code = datamodel.KRB_ERR_GENERIC // TODO
		err.E_text = "Sname missing in request body"
		return false, err, noTgsRep()
	}
	sname := req.Req_body.Sname

	// get principal info from database
	serverPrinc, ok := a.database.GetPrincipal(sname)
	if !ok {
		return false, newTgsErrorFromReq(req, datamodel.KDC_ERR_S_PRINCIPAL_UNKNOWN), noTgsRep()
	}

	apReq, err := a.getApReqFromTgsReq(req)
	ticket := apReq.Ticket
	if err != nil {
		return false, newTgsErrorFromReq(req, datamodel.KDC_ERR_PADATA_TYPE_NOSUPP), noTgsRep()
	}
	notTgt := true // TODO implement detection, used only in condition below
	kdcFlags := datamodel.KDCOptions(req.Req_body.Kdc_options)
	renewFlag := kdcFlags.Get(datamodel.KDC_FLAG_RENEW)
	validateFlag := kdcFlags.Get(datamodel.KDC_FLAG_VALIDATE)
	proxyFlag := kdcFlags.Get(datamodel.KDC_FLAG_PROXY)
	if notTgt && (renewFlag || validateFlag || proxyFlag) && ticket.Sname.Equal(sname) {
		// TODO so what?
	}
	err, encTicket := decryptTicket(a.crypto, serverPrinc.SecretKeys, ticket)
	if err != nil {
		return false, newTgsErrorFromReq(req, datamodel.KRB_AP_ERR_BAD_INTEGRITY), noTgsRep()
	}

	currentSessionKey := encTicket.Key
	err, encAuth := decryptAuth(a.crypto, currentSessionKey, apReq.Authenticator)
	if err != nil {
		return false, newTgsErrorFromReq(req, datamodel.KRB_AP_ERR_BAD_INTEGRITY), noTgsRep()
	}

	errCode := verifyReqChecksum(a.crypto, currentSessionKey, encAuth.Cksum, req.Req_body)
	if errCode != datamodel.KDC_ERR_NONE {
		return false, newTgsErrorFromReq(req, errCode), noTgsRep()
	}

	// TODO
	//As discussed in Section 3.1.2, the KDC MUST send a valid KRB_TGS_REP
	//message if it receives a KRB_TGS_REQ message identical to one it has
	//recently processed.  However, if the authenticator is a replay, but
	//the rest of the request is not identical, then the KDC SHOULD return
	//KRB_AP_ERR_REPEAT.

	// TODO implement cross-realm requests

	// update lr info
	authTime, _ := kerberosNow()
	Cname := encTicket.Cname
	a.database.UpdateLastReq(Cname, datamodel.LR_TYPE_ANY, authTime)
	a.database.UpdateLastReq(Cname, datamodel.LR_TYPE_INITIAL_REQUEST, authTime)
	// retrieve updated lr info
	clientPrinc, ok := a.database.GetPrincipal(Cname)
	if !ok {
		return false, newTgsErrorFromReq(req, datamodel.KDC_ERR_C_PRINCIPAL_UNKNOWN), noTgsRep()
	}

	err, startTime, invalid := a.getTgsStarttime(req, encTicket)

	// set ticket flags
	flags := datamodel.NewTicketFlags()
	flags.Set(datamodel.TKT_FLAG_MAY_POSTDATE, kdcFlags.Get(datamodel.KDC_FLAG_ALLOW_POSTDATE))
	flags.Set(datamodel.TKT_FLAG_POSTDATED, kdcFlags.Get(datamodel.KDC_FLAG_POSTDATED))
	flags.Set(datamodel.TKT_FLAG_RENEWABLE, kdcFlags.Get(datamodel.KDC_FLAG_RENEWABLE))
	flags.Set(datamodel.TKT_FLAG_INVALID, invalid)
	flags.Set(datamodel.TKT_FLAG_INITIAL, true)

	ticketAddresses := encTicket.Caddr

	encTicketFlags := datamodel.TicketFlags(encTicket.Flags)
	tgtProxiable := encTicketFlags.Get(datamodel.TKT_FLAG_PROXIABLE)
	tgtForwardable := encTicketFlags.Get(datamodel.TKT_FLAG_FORWARDABLE)
	if tgtProxiable || tgtForwardable {
		// TODO The PROXY option will not be honored on
		flags.Set(datamodel.KDC_FLAG_FORWARDED, tgtForwardable)
		flags.Set(datamodel.KDC_FLAG_PROXY, tgtProxiable)
		ticketAddresses = req.Req_body.Addresses
	}

	// TODO support ENC-TKT-IN-SKEY

	//TODO serverPrincIsTgs := Sname.Equal(a.tgsPrinc)
	// TODO check server is registered in the realm of the KDC
	now, _ := datamodel.KerberosTimeNowUsec()
	if kdcFlags.Get(datamodel.KDC_FLAG_RENEW) {
		validated :=
			encTicketFlags.Get(datamodel.TKT_FLAG_RENEWABLE) &&
				!encTicketFlags.Get(datamodel.TKT_FLAG_INVALID) &&
				datamodel.KerberosTime(encTicket.Renew_till).ToUnix() > now.ToUnix()
		if !validated {
			krbErr := datamodel.NewErrorC(a.realm, sname, datamodel.KRB_AP_ERR_TKT_EXPIRED)
			return false, krbErr, noTgsRep()
		}
	}
	if kdcFlags.Get(datamodel.KDC_FLAG_VALIDATE) {
		validated := (encTicketFlags.Get(datamodel.TKT_FLAG_INVALID) &&
			datamodel.KerberosTime(encTicket.Starttime).ToUnix()> now.ToUnix())
		if !validated {
			krbErr := datamodel.NewErrorC(a.realm, sname, datamodel.KRB_AP_ERR_TKT_NYV)
			return false, krbErr, noTgsRep()
		}
	}
	if kdcFlags.Get(datamodel.KDC_FLAG_PROXY) {
		validated := encTicketFlags.Get(datamodel.TKT_FLAG_PROXIABLE)
		if !validated {
			krbErr := datamodel.NewErrorC(a.realm, sname, datamodel.KDC_ERR_POLICY)
			return false, krbErr, noTgsRep()
		}
	}

	var renewTill datamodel.KerberosTime
	if encTicketFlags.Get(datamodel.KDC_FLAG_RENEWABLE) {
		renewTill = datamodel.KerberosTime(encTicket.Renew_till)
	}
	if a.revocationHotlist.IsRevoked(datamodel.KerberosTime(encTicket.Authtime)) {
		return false, newTgsErrorFromReq(req, datamodel.KDC_ERR_TGT_REVOKED), noTgsRep()
	}

	oldStartTime := encTicket.Authtime
	if !encTicket.Starttime.IsZero() {
		oldStartTime = encTicket.Starttime
	}
	var appMaxLifetime int64 = math.MaxInt64
	expirationTime := getTicketExpirationTime(
		datamodel.KerberosTime(req.Req_body.Till),
		datamodel.KerberosTime(encTicket.Endtime), startTime, appMaxLifetime, a.maxExpirationTime,
		datamodel.KerberosTime(encTicket.Renew_till),
		datamodel.KerberosTime(oldStartTime)) // TODO check KDC_FLAG_RENEW

	if ok, err := a.checkMinLifetime(datamodel.KDC_REQ(req), startTime, expirationTime); !ok {
		return false, err, noTgsRep()
	}

	effectiveSessionKey := currentSessionKey
	if encAuth.Subkey.IsEmpty() {
		effectiveSessionKey = encAuth.Subkey
	}

	// fill ticket info
	encRepTicket := datamodel.EncTicketPart{
		Flags:             flags.ToWire(),
		Key:               effectiveSessionKey,
		Crealm:            encTicket.Crealm,
		Cname:             encTicket.Cname,
		Transited:         encTicket.Transited, // TODO implement KDC_ERR_TRTYPE_NOSUPP
		Authtime:          encTicket.Authtime,
		Starttime:         startTime.ToWire(),
		Endtime:           encTicket.Endtime,
		Renew_till:        renewTill.ToWire(),
		Caddr:             ticketAddresses,
		Authorization_data: encTicket.Authorization_data,
	}
	repTicket := datamodel.Ticket{
		Realm:   a.realm,
		Sname:   sname,
		Enc_part: a.encryptTicketPart(serverPrinc.SecretKeys, encRepTicket),
	}
	encAsRep := datamodel.EncASRepPart{
		Key:           effectiveSessionKey,
		Last_req:       clientPrinc.LastReq,
		Nonce:         req.Req_body.Nonce,
		//Key_expiration: nil,
		Flags:         flags.ToWire(),
		Authtime:      authTime.ToWire(),
		Starttime:     startTime.ToWire(),
		Endtime:       expirationTime.ToWire(),
		Renew_till:     renewTill.ToWire(),
		Srealm:        a.realm,
		Sname:         sname,
		Caddr:         req.Req_body.Addresses,
	}
	rep = datamodel.TGS_REP{
		Padata:  make([]datamodel.PA_DATA, 0), // TODO
		Crealm:  req.Req_body.Realm,
		Cname:   Cname,
		Ticket:  repTicket,
		Enc_part: a.encryptAsRepPart(effectiveSessionKey, encAsRep),
	}

	return true, datamodel.NoError(), rep
}

func getTicketExpirationTime(requestedTill datamodel.KerberosTime, oldEndTime datamodel.KerberosTime,
	startTime datamodel.KerberosTime, appMaxLifetime int64, realmMaxExpirationTime int64,
	oldRenewTill datamodel.KerberosTime, oldStartTime datamodel.KerberosTime) datamodel.KerberosTime {

	if requestedTill == datamodel.KerberosEpoch() {
		requestedTill.SetTimestamp(math.MaxInt64)
	}
	calculatedEndTime := startTime.ToUnix() + min64(appMaxLifetime, realmMaxExpirationTime)
	endtime := min64(requestedTill.ToUnix(), min64(oldEndTime.ToUnix(), calculatedEndTime))

	if !oldRenewTill.IsEmpty() {
		oldLifetime := oldEndTime.ToUnix() - oldStartTime.ToUnix()
		endtime = min64(oldRenewTill.ToUnix(), oldStartTime.ToUnix() +oldLifetime)
	}
	return datamodel.KerberosTimeFromUnix(endtime)
}

func (a *authenticationServer) getTgsStarttime(req datamodel.TGS_REQ, encTicket datamodel.EncTicketPart) (err datamodel.KRB_ERROR, t datamodel.KerberosTime, invalid bool) {
	now, _ := kerberosNow()
	if req.Req_body.From.IsZero() {
		return noError(), now, false
	}
	difference := req.Req_body.From.Unix() - time.Now().Unix() // -past, +future
	if difference < 0 {
		return noError(), now, false
	}
	kdcOptions := datamodel.KDCOptions(req.Req_body.Kdc_options)
	encTicketFlags := datamodel.TicketFlags(encTicket.Flags)
	postdate := kdcOptions.Get(datamodel.KDC_FLAG_ALLOW_POSTDATE)
	postdated := kdcOptions.Get(datamodel.KDC_FLAG_POSTDATED)
	mayPostdate := encTicketFlags.Get(datamodel.TKT_FLAG_MAY_POSTDATE)
	if !postdate && difference < a.clockSkew {
		return noError(), now, false
	}
	if (!postdated || !mayPostdate) && difference > a.clockSkew {
		err := newTgsError(req)
		err.Error_code = datamodel.KDC_ERR_CANNOT_POSTDATE
		return err, datamodel.KerberosTime{}, false
	}
	// check against policy
	if difference > a.maxPostdate {
		err := newTgsError(req)
		err.Error_code = datamodel.KDC_ERR_CANNOT_POSTDATE
		return err, datamodel.KerberosTime{}, false
	}
	// postdated ticket beyond clock skew clock skew or non-postdated within clock skew
	return noError(), datamodel.KerberosTime(req.Req_body.From), true
}

func verifyReqChecksum(cryptof crypto.ChecksumFactory, key datamodel.EncryptionKey, clientCksum datamodel.Checksum, reqBody datamodel.KDC_REQ_BODY) int32 {
	// TODO check collision proof => KRB_AP_ERR_INAPP_CKSUM
	// TODO check supported => KDC_ERR_SUMTYPE_NOSUPP
	algo := cryptof.CreateChecksum(clientCksum.Cksumtype)
	mic := crypto.MIC(clientCksum.Checksum)
	body := make([]byte, 0) // TODO serialization
	if !algo.VerifyMic(key, body, mic) {
		return datamodel.KRB_AP_ERR_MODIFIED
	}
	return datamodel.KDC_ERR_NONE
}

func (srv authenticationServer) getApReqFromTgsReq(req datamodel.TGS_REQ) (apReq datamodel.AP_REQ, err error) {
	found := false
	for _, padata := range req.Padata {
		if padata.Padata_type == datamodel.PA_T_TGS_REQ {
			err = srv.serializer.Unmarshal(padata.Padata_value, &apReq)
			if err != nil {
				return
			}
			found = true
			break
		}
	}
	if found {
		return apReq, nil
	}
	return apReq, errors.New("TGS request did not contain Ticket in preauth data")
}

func decryptTicket(crypto crypto.EncryptionFactory, keys []datamodel.EncryptionKey, tgt datamodel.Ticket) (err error, res datamodel.EncTicketPart) {
	// TODO picking ticket
	key := keys[0]
	algo := crypto.Create(key.Keytype)
	err = algo.Decrypt(tgt.Enc_part, key, &res)
	return err, res
}

func decryptAuth(crypto crypto.EncryptionFactory, key datamodel.EncryptionKey, data datamodel.EncryptedData) (err error, res datamodel.Authenticator) {
	algo := crypto.Create(key.Keytype)
	err = algo.Decrypt(data, key, &res)
	return err, res
}

func noTgsRep() datamodel.TGS_REP {
	return datamodel.TGS_REP{}
}
