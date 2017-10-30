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
	AuthenticationServerExchange(datamodel.AsReq) (ok bool, err datamodel.KrbError, rep datamodel.AsRep)
	TgsExchange(datamodel.TgsReq) (ok bool, err datamodel.KrbError, rep datamodel.TgsRep)
	RevokeTickets(starTime, endTime datamodel.KerberosTime)
}

const (
	ONE_DAY = int64(24 * 60 * 60)
)

func NewKdcServer(realm datamodel.Realm, database database.KdcDatabase, crypto crypto.Factory) KdcServer {
	maxLifetime := ONE_DAY
	return &authenticationServer{
		realm:             realm,
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

func (a *authenticationServer) AuthenticationServerExchange(req datamodel.AsReq) (ok bool, err datamodel.KrbError, rep datamodel.AsRep) {
	// initial integrity verification
	if req.ReqBody.SName == nil || req.ReqBody.CName == nil {
		err := newAsError(req)
		err.ErrorCode = 42
		err.EText = "sname or cname missing in request body"
		return false, err, noRep()
	}
	sname := *req.ReqBody.SName

	cname := *req.ReqBody.CName
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
	if !a.checkEtypes(req.ReqBody.EType) {
		return false, algorithmNotFoundError(req), noRep()
	}
	ok, clientKey := a.getSupportedKey(req.ReqBody.EType, clientPrinc.SecretKeys)
	sessionAlgo := a.selectSessionKeyAlgo(req.ReqBody.EType)
	sessionKey := sessionAlgo.GenerateKey()
	// TODO support POSTDATE
	err, startTime, invalid := a.getStarttime(req)
	if err.ErrorCode != datamodel.KDC_ERR_NONE {
		return false, err, noRep()
	}
	expirationTime := getTgtExpirationTime(
		a.maxExpirationTime, clientPrinc.MaxExpirationTime, startTime, req.ReqBody.Till)
	if ok, err := a.checkMinLifetime(datamodel.KdcReq(req), startTime, expirationTime); !ok {
		return false, err, noRep()
	}
	kdcFlags := req.ReqBody.KdcOptions
	renewable := kdcFlags[datamodel.KDC_FLAG_RENEWABLE_OK]
	var renewTill *datamodel.KerberosTime
	if renewable {
		renew := a.calcNextRenewTill(clientPrinc, serverPrinc, req.ReqBody.RTime)
		renewTill = &renew
	}

	// update lr info
	authTime, _ := kerberosNow()
	a.database.UpdateLastReq(cname, datamodel.LR_TYPE_ANY, authTime)
	a.database.UpdateLastReq(cname, datamodel.LR_TYPE_INITIAL_REQUEST, authTime)

	// set ticket flags
	flags := datamodel.NewTicketFlags()
	flags[datamodel.TKT_FLAG_FORWARDABLE] = kdcFlags[datamodel.KDC_FLAG_FORWARDABLE]
	flags[datamodel.TKT_FLAG_MAY_POSTDATE] = kdcFlags[datamodel.KDC_FLAG_ALLOW_POSTDATE]
	flags[datamodel.TKT_FLAG_POSTDATED] = kdcFlags[datamodel.KDC_FLAG_POSTDATED]
	flags[datamodel.TKT_FLAG_PROXIABLE] = kdcFlags[datamodel.KDC_FLAG_PROXIABLE]
	flags[datamodel.TKT_FLAG_RENEWABLE] = kdcFlags[datamodel.KDC_FLAG_RENEWABLE]
	flags[datamodel.TKT_FLAG_INVALID] = invalid
	flags[datamodel.TKT_FLAG_INITIAL] = true

	// fill ticket info
	encTicket := datamodel.EncTicketPart{
		Flags:  flags,
		Key:    sessionKey,
		CRealm: req.ReqBody.Realm,
		CName:  cname,
		//Transited         TransitedEncoding
		AuthTime:  authTime,
		StartTime: &startTime,
		EndTime:   expirationTime,
		RenewTill: renewTill,
		CAddr:     req.ReqBody.Addresses,
		//AuthorizationData AuthorizationData
	}
	ticket := datamodel.Ticket{
		Realm:   a.realm,
		SName:   sname,
		EncPart: a.encryptTicketPart(serverPrinc.SecretKeys, encTicket),
	}
	encAsRep := datamodel.EncAsRepPart{
		Key:           sessionKey,
		LastReq:       clientPrinc.LastReq,
		Nonce:         req.ReqBody.Nonce,
		KeyExpiration: keyExpirationFromLastReq(clientPrinc.LastReq),
		Flags:         flags,
		AuthTime:      authTime,
		StartTime:     &startTime,
		EndTime:       expirationTime,
		RenewTill:     renewTill,
		SRealm:        a.realm,
		SName:         sname,
		CAddr:         req.ReqBody.Addresses,
	}
	rep = datamodel.AsRep{
		PaData:  make([]datamodel.PaData, 0), // TODO
		CRealm:  req.ReqBody.Realm,
		CName:   cname,
		Ticket:  ticket,
		EncPart: a.encryptAsRepPart(clientKey, encAsRep),
	}
	return true, noError(), rep
}

func newAsErrorFromReq(req datamodel.AsReq, code int32) datamodel.KrbError {
	return newErrorFromReq(datamodel.KdcReq(req), code)
}

func newTgsErrorFromReq(req datamodel.TgsReq, code int32) datamodel.KrbError {
	return newErrorFromReq(datamodel.KdcReq(req), code)
}

func newErrorFromReq(req datamodel.KdcReq, code int32) datamodel.KrbError {
	ctime := time.Now()
	return datamodel.KrbError{
		CTime:     datamodel.KerberosTime{ctime.Unix()},
		CUSec:     int32(ctime.Nanosecond() / 1000),
		ErrorCode: code,
		//CName: *req.ReqBody.CName,
		CRealm: req.ReqBody.Realm,
		//SName:     *req.ReqBody.SName,
		EData: make([]byte, 0),
	}
}

func (a *authenticationServer) checkEtypes(etypes []int32) bool {
	for _, requested := range etypes {
		if isSupportedEtype(a.crypto, requested) {
			return true
		}
	}
	return false
}

func (a *authenticationServer) getSupportedKey(algo []int32, clientKeys []datamodel.EncryptionKey) (bool, datamodel.EncryptionKey) {
	for _, requested := range algo {
		if !isSupportedEtype(a.crypto, requested) {
			continue
		}
		for _, key := range clientKeys {
			if key.KeyType == requested {
				return true, key
			}
		}
	}
	return false, datamodel.EncryptionKey{}
}

func (a *authenticationServer) selectSessionKeyAlgo(algo []int32) crypto.Algorithm {
	for _, requested := range algo {
		if isSupportedEtype(a.crypto, requested) {
			return a.crypto.Create(requested)
		}
	}
	panic("not found supported algorithm")
}

func isSupportedEtype(factory crypto.EncryptionFactory, requested int32) bool {
	for _, supported := range factory.SupportedETypes() {
		if supported == requested {
			return true
		}
	}
	return false
}

func algorithmNotFoundError(req datamodel.AsReq) datamodel.KrbError {
	now := time.Now()
	return datamodel.KrbError{
		CTime:     datamodel.KerberosTime{now.Unix()},
		CUSec:     int32(now.Nanosecond() / 1000),
		ErrorCode: datamodel.KDC_ERR_ETYPE_NOSUPP,
		CRealm:    req.ReqBody.Realm,
		SName:     *req.ReqBody.SName,
		EText:     "Neither of requested encryption types is supported",
	}
}

func (a *authenticationServer) getStarttime(req datamodel.AsReq) (err datamodel.KrbError, t datamodel.KerberosTime, invalid bool) {
	now, _ := kerberosNow()
	if req.ReqBody.From == nil {
		return noError(), now, false
	}
	difference := req.ReqBody.From.Timestamp - time.Now().Unix() // -past, +future
	if difference < 0 {
		return noError(), now, false
	}
	postdated := req.ReqBody.KdcOptions[datamodel.KDC_FLAG_POSTDATED]
	if postdated && difference < a.clockSkew {
		return noError(), now, false
	}
	if !postdated && difference > a.clockSkew {
		err := newAsError(req)
		err.ErrorCode = datamodel.KDC_ERR_CANNOT_POSTDATE
		return err, datamodel.KerberosTime{}, false
	}
	// check against policy
	if postdated && difference > a.maxPostdate {
		err := newAsError(req)
		err.ErrorCode = datamodel.KDC_ERR_CANNOT_POSTDATE
		return err, datamodel.KerberosTime{}, false
	}
	// postdated ticket beyond clock skew clock skew or non-postdated within clock skew
	return noError(), *req.ReqBody.From, true

}

func getTgtExpirationTime(
	realmExpirationTime int64,
	princExpirationTime int64,
	startTime datamodel.KerberosTime,
	requestedTill datamodel.KerberosTime) datamodel.KerberosTime {

	if requestedTill == datamodel.KerberosEpoch() {
		requestedTill.Timestamp = math.MaxInt64
	}
	maxExpiration := min64(princExpirationTime, realmExpirationTime)
	enforced := min64(requestedTill.Timestamp, startTime.Timestamp+maxExpiration)
	return datamodel.KerberosTime{Timestamp: enforced}
}

// TODO
func (a *authenticationServer) preauthCheck(req datamodel.AsReq) (ok bool, err datamodel.KrbError) {
	return true, noError()
}

func newAsError(req datamodel.AsReq) datamodel.KrbError {
	return newKdcError(datamodel.KdcReq(req))
}

func newTgsError(req datamodel.TgsReq) datamodel.KrbError {
	return newKdcError(datamodel.KdcReq(req))
}

func newKdcError(req datamodel.KdcReq) datamodel.KrbError {
	ctime, usec := kerberosNow()
	err := datamodel.KrbError{
		CTime: ctime,
		CUSec: usec,
		//ErrorCode: ,
		CRealm: req.ReqBody.Realm,
		//EText:     ,
		//EData:     make([]byte, 0),
	}
	if req.ReqBody.SName != nil {
		err.SName = *req.ReqBody.SName
	}
	return err
}

func (a *authenticationServer) checkMinLifetime(req datamodel.KdcReq, startTime datamodel.KerberosTime, expirationTime datamodel.KerberosTime) (bool, datamodel.KrbError) {
	if expirationTime.Timestamp-startTime.Timestamp < a.minTicketLifetime {
		err := newKdcError(req)
		err.ErrorCode = datamodel.KDC_ERR_NEVER_VALID
		return false, err
	} else {
		return true, noError()
	}
}

func (a *authenticationServer) calcNextRenewTill(sprinc database.PrincipalInfo, cprinc database.PrincipalInfo, rtime *datamodel.KerberosTime) datamodel.KerberosTime {
	maxRenewTime := min64(min64(sprinc.MaxRenewTime, cprinc.MaxRenewTime), a.maxRenewTime)
	if rtime != nil {
		maxRenewTime = min64(maxRenewTime, rtime.Timestamp)
	}
	return datamodel.KerberosTime{maxRenewTime}
}

func (a *authenticationServer) encryptTicketPart(keys []datamodel.EncryptionKey, ticket datamodel.EncTicketPart) datamodel.EncryptedData {
	// TODO picking logic
	key := keys[0]
	algo := a.crypto.Create(key.KeyType)
	err, data := algo.Encrypt(key, ticket)
	if err != nil {
		panic(err) // TODO should never happen
	}
	return data
}

func (a *authenticationServer) encryptAsRepPart(key datamodel.EncryptionKey, encAsRep datamodel.EncAsRepPart) datamodel.EncryptedData {
	algo := a.crypto.Create(key.KeyType)
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


func noError() datamodel.KrbError {
	return datamodel.KrbError{}
}

func noRep() datamodel.AsRep {
	return datamodel.AsRep{}
}

func kerberosNow() (t datamodel.KerberosTime, usec int32) {
	return datamodel.KerberosTimeNowUsec()
}

func keyExpirationFromLastReq(lastReq datamodel.LastReq) *datamodel.KerberosTime {
	minElem := datamodel.KerberosTime{math.MaxInt64}
	for _, elem := range lastReq {
		if elem.LrType == datamodel.LR_TYPE_PASSWORD_EXPIRES || elem.LrType == datamodel.LR_TYPE_ACCOUNT_EXPIRES {
			if elem.LrValue.Timestamp < minElem.Timestamp {
				minElem.Timestamp = elem.LrValue.Timestamp
			}
		}
	}
	if minElem.Timestamp == math.MaxInt64 {
		return nil
	} else {
		return &minElem
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

func (a *authenticationServer) TgsExchange(req datamodel.TgsReq) (ok bool, kerr datamodel.KrbError, rep datamodel.TgsRep) {
	if req.ReqBody.Realm != a.realm {
		// appr cross-realm key MUST be used
		return false, datamodel.NewErrorGeneric(a.realm, datamodel.PrincipalName{}, "Cross-realm auth not implemented"), noTgsRep()
	}
	// initial integrity verification
	if req.ReqBody.SName == nil {
		err := newTgsError(req)
		err.ErrorCode = datamodel.KRB_ERR_GENERIC // TODO
		err.EText = "sname missing in request body"
		return false, err, noTgsRep()
	}
	sname := *req.ReqBody.SName

	// get principal info from database
	serverPrinc, ok := a.database.GetPrincipal(sname)
	if !ok {
		return false, newTgsErrorFromReq(req, datamodel.KDC_ERR_S_PRINCIPAL_UNKNOWN), noTgsRep()
	}

	apReq, err := getApReqFromTgsReq(req)
	ticket := apReq.Ticket
	if err != nil {
		return false, newTgsErrorFromReq(req, datamodel.KDC_ERR_PADATA_TYPE_NOSUPP), noTgsRep()
	}
	notTgt := true // TODO implement detection, used only in condition below
	kdcFlags := req.ReqBody.KdcOptions
	renewFlag := kdcFlags[datamodel.KDC_FLAG_RENEW]
	validateFlag := kdcFlags[datamodel.KDC_FLAG_VALIDATE]
	proxyFlag := kdcFlags[datamodel.KDC_FLAG_PROXY]
	if notTgt && (renewFlag || validateFlag || proxyFlag) && ticket.SName.Equal(sname) {
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

	errCode := verifyReqChecksum(a.crypto, currentSessionKey, encAuth.CKSum, req.ReqBody)
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
	cname := encTicket.CName
	a.database.UpdateLastReq(cname, datamodel.LR_TYPE_ANY, authTime)
	a.database.UpdateLastReq(cname, datamodel.LR_TYPE_INITIAL_REQUEST, authTime)
	// retrieve updated lr info
	clientPrinc, ok := a.database.GetPrincipal(cname)
	if !ok {
		return false, newTgsErrorFromReq(req, datamodel.KDC_ERR_C_PRINCIPAL_UNKNOWN), noTgsRep()
	}

	err, startTime, invalid := a.getTgsStarttime(req, encTicket)

	// set ticket flags
	flags := datamodel.NewTicketFlags()
	flags[datamodel.TKT_FLAG_MAY_POSTDATE] = kdcFlags[datamodel.KDC_FLAG_ALLOW_POSTDATE]
	flags[datamodel.TKT_FLAG_POSTDATED] = kdcFlags[datamodel.KDC_FLAG_POSTDATED]
	flags[datamodel.TKT_FLAG_RENEWABLE] = kdcFlags[datamodel.KDC_FLAG_RENEWABLE]
	flags[datamodel.TKT_FLAG_INVALID] = invalid
	flags[datamodel.TKT_FLAG_INITIAL] = true

	ticketAddresses := encTicket.CAddr

	tgtProxiable := encTicket.Flags[datamodel.TKT_FLAG_PROXIABLE]
	tgtForwardable := encTicket.Flags[datamodel.TKT_FLAG_FORWARDABLE]
	if tgtProxiable || tgtForwardable {
		// TODO The PROXY option will not be honored on
		flags[datamodel.KDC_FLAG_FORWARDED] = tgtForwardable
		flags[datamodel.KDC_FLAG_PROXY] = tgtProxiable
		ticketAddresses = req.ReqBody.Addresses
	}

	// TODO support ENC-TKT-IN-SKEY

	//TODO serverPrincIsTgs := sname.Equal(a.tgsPrinc)
	// TODO check server is registered in the realm of the KDC
	now, _ := datamodel.KerberosTimeNowUsec()
	if kdcFlags[datamodel.KDC_FLAG_RENEW] {
		validated :=
			encTicket.Flags[datamodel.TKT_FLAG_RENEWABLE] &&
				!encTicket.Flags[datamodel.TKT_FLAG_INVALID] &&
				encTicket.RenewTill.Timestamp > now.Timestamp
		if !validated {
			krbErr := datamodel.NewErrorC(a.realm, sname, datamodel.KRB_AP_ERR_TKT_EXPIRED)
			return false, krbErr, noTgsRep()
		}
	}
	if kdcFlags[datamodel.KDC_FLAG_VALIDATE] {
		validated := (encTicket.Flags[datamodel.TKT_FLAG_INVALID] &&
			encTicket.StartTime.Timestamp > now.Timestamp)
		if !validated {
			krbErr := datamodel.NewErrorC(a.realm, sname, datamodel.KRB_AP_ERR_TKT_NYV)
			return false, krbErr, noTgsRep()
		}
	}
	if kdcFlags[datamodel.KDC_FLAG_PROXY] {
		validated := encTicket.Flags[datamodel.TKT_FLAG_PROXIABLE]
		if !validated {
			krbErr := datamodel.NewErrorC(a.realm, sname, datamodel.KDC_ERR_POLICY)
			return false, krbErr, noTgsRep()
		}
	}

	var renewTill *datamodel.KerberosTime
	if encTicket.Flags[datamodel.KDC_FLAG_RENEWABLE] {
		renewTill = encTicket.RenewTill
	}
	if a.revocationHotlist.IsRevoked(encTicket.AuthTime) {
		return false, newTgsErrorFromReq(req, datamodel.KDC_ERR_TGT_REVOKED), noTgsRep()
	}

	oldStartTime := encTicket.AuthTime
	if encTicket.StartTime != nil {
		oldStartTime = *encTicket.StartTime
	}
	var appMaxLifetime int64 = math.MaxInt64
	expirationTime := getTicketExpirationTime(
		req.ReqBody.Till, encTicket.EndTime, startTime, appMaxLifetime, a.maxExpirationTime,
		encTicket.RenewTill, oldStartTime) // TODO check KDC_FLAG_RENEW

	if ok, err := a.checkMinLifetime(datamodel.KdcReq(req), startTime, expirationTime); !ok {
		return false, err, noTgsRep()
	}

	effectiveSessionKey := currentSessionKey
	if encAuth.SubKey != nil {
		effectiveSessionKey = *encAuth.SubKey
	}

	// fill ticket info
	encRepTicket := datamodel.EncTicketPart{
		Flags:             flags,
		Key:               effectiveSessionKey,
		CRealm:            encTicket.CRealm,
		CName:             encTicket.CName,
		Transited:         encTicket.Transited, // TODO implement KDC_ERR_TRTYPE_NOSUPP
		AuthTime:          encTicket.AuthTime,
		StartTime:         &startTime,
		EndTime:           encTicket.EndTime,
		RenewTill:         renewTill,
		CAddr:             ticketAddresses,
		AuthorizationData: encTicket.AuthorizationData,
	}
	repTicket := datamodel.Ticket{
		Realm:   a.realm,
		SName:   sname,
		EncPart: a.encryptTicketPart(serverPrinc.SecretKeys, encRepTicket),
	}
	encAsRep := datamodel.EncAsRepPart{
		Key:           effectiveSessionKey,
		LastReq:       clientPrinc.LastReq,
		Nonce:         req.ReqBody.Nonce,
		KeyExpiration: nil,
		Flags:         flags,
		AuthTime:      authTime,
		StartTime:     &startTime,
		EndTime:       expirationTime,
		RenewTill:     renewTill,
		SRealm:        a.realm,
		SName:         sname,
		CAddr:         req.ReqBody.Addresses,
	}
	rep = datamodel.TgsRep{
		PaData:  make([]datamodel.PaData, 0), // TODO
		CRealm:  req.ReqBody.Realm,
		CName:   cname,
		Ticket:  repTicket,
		EncPart: a.encryptAsRepPart(effectiveSessionKey, encAsRep),
	}

	return true, datamodel.NoError(), rep
}

func getTicketExpirationTime(requestedTill datamodel.KerberosTime, oldEndTime datamodel.KerberosTime,
	startTime datamodel.KerberosTime, appMaxLifetime int64, realmMaxExpirationTime int64,
	oldRenewTill *datamodel.KerberosTime, oldStartTime datamodel.KerberosTime) datamodel.KerberosTime {

	if requestedTill == datamodel.KerberosEpoch() {
		requestedTill.Timestamp = math.MaxInt64
	}
	calculatedEndTime := startTime.Timestamp + min64(appMaxLifetime, realmMaxExpirationTime)
	endtime := min64(requestedTill.Timestamp, min64(oldEndTime.Timestamp, calculatedEndTime))

	if oldRenewTill != nil {
		oldLifetime := oldEndTime.Timestamp - oldStartTime.Timestamp
		endtime = min64(oldRenewTill.Timestamp, oldStartTime.Timestamp+oldLifetime)
	}
	return datamodel.KerberosTime{endtime}
}

func (a *authenticationServer) getTgsStarttime(req datamodel.TgsReq, encTicket datamodel.EncTicketPart) (err datamodel.KrbError, t datamodel.KerberosTime, invalid bool) {
	now, _ := kerberosNow()
	if req.ReqBody.From == nil {
		return noError(), now, false
	}
	difference := req.ReqBody.From.Timestamp - time.Now().Unix() // -past, +future
	if difference < 0 {
		return noError(), now, false
	}
	postdate := req.ReqBody.KdcOptions[datamodel.KDC_FLAG_ALLOW_POSTDATE]
	postdated := req.ReqBody.KdcOptions[datamodel.KDC_FLAG_POSTDATED]
	mayPostdate := encTicket.Flags[datamodel.TKT_FLAG_MAY_POSTDATE]
	if !postdate && difference < a.clockSkew {
		return noError(), now, false
	}
	if (!postdated || !mayPostdate) && difference > a.clockSkew {
		err := newTgsError(req)
		err.ErrorCode = datamodel.KDC_ERR_CANNOT_POSTDATE
		return err, datamodel.KerberosTime{}, false
	}
	// check against policy
	if difference > a.maxPostdate {
		err := newTgsError(req)
		err.ErrorCode = datamodel.KDC_ERR_CANNOT_POSTDATE
		return err, datamodel.KerberosTime{}, false
	}
	// postdated ticket beyond clock skew clock skew or non-postdated within clock skew
	return noError(), *req.ReqBody.From, true
}

func verifyReqChecksum(cryptof crypto.ChecksumFactory, key datamodel.EncryptionKey, clientCksum *datamodel.Checksum, reqBody datamodel.KdcReqBody) int32 {
	// TODO check collision proof => KRB_AP_ERR_INAPP_CKSUM
	// TODO check supported => KDC_ERR_SUMTYPE_NOSUPP
	algo := cryptof.CreateChecksum(clientCksum.CkSumType)
	mic := crypto.MIC(clientCksum.Checksum)
	body := make([]byte, 0) // TODO serialization
	if !algo.VerifyMic(key, body, mic) {
		return datamodel.KRB_AP_ERR_MODIFIED
	}
	return datamodel.KDC_ERR_NONE
}

func getApReqFromTgsReq(req datamodel.TgsReq) (apReq datamodel.ApReq, err error) {
	found := false
	for _, padata := range req.PaData {
		if padata.Value.PaType() == datamodel.PA_TGS_REQ {
			apReq = datamodel.ApReq(padata.Value.(datamodel.PaTgsReq))
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
	algo := crypto.Create(key.KeyType)
	err = algo.Decrypt(tgt.EncPart, key, &res)
	return err, res
}

func decryptAuth(crypto crypto.EncryptionFactory, key datamodel.EncryptionKey, data datamodel.EncryptedData) (err error, res datamodel.Authenticator) {
	algo := crypto.Create(key.KeyType)
	err = algo.Decrypt(data, key, &res)
	return err, res
}

func noTgsRep() datamodel.TgsRep {
	return datamodel.TgsRep{}
}
