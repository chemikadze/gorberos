package asrv

import (
	"fmt"
	"github.com/chemikadze/gorberos/crypto"
	"github.com/chemikadze/gorberos/database"
	"github.com/chemikadze/gorberos/datamodel"
	"math"
	"time"
)

type AuthenticationServer interface {
	AuthenticationServerExchange(datamodel.AsReq) (ok bool, err datamodel.KrbError, rep datamodel.AsRep)
}

type authenticationServer struct {
	database          database.KdcDatabase
	crypto            crypto.EncryptionFactory
	clockSkew         int64
	minTicketLifetime int64
	maxRenewTime      int64
	realm             datamodel.Realm
	maxPostdate       int64
	maxExpirationTime int64
}

func (a *authenticationServer) AuthenticationServerExchange(req datamodel.AsReq) (ok bool, err datamodel.KrbError, rep datamodel.AsRep) {
	// initial integrity verification
	if req.ReqBody.SName == nil {
		err := newEmptyError(req)
		err.ErrorCode = 42
		err.EText = "sname missing in request body"
		return false, err, noRep()
	}
	sname := *req.ReqBody.SName

	cname := req.ReqBody.CName
	// get principal info from database
	clientPrinc, ok := a.database.GetPrincipal(cname)
	if !ok {
		return false, princNotFoundError(req, cname), noRep()
	}
	serverPrinc, ok := a.database.GetPrincipal(sname)
	if !ok {
		return false, princNotFoundError(req, sname), noRep()
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
	sessionKey := a.generateSessionKey(sessionAlgo)
	// TODO support POSTDATE
	err, startTime, invalid := a.getStarttime(req)
	if err.ErrorCode != datamodel.KDC_ERR_NONE {
		return false, err, noRep()
	}
	expirationTime := getExpirationTime(
		a.maxExpirationTime, clientPrinc.MaxExpirationTime, startTime, req.ReqBody.Till)
	if ok, err := a.checkMinLifetime(req, startTime, expirationTime); !ok {
		return false, err, noRep()
	}
	kdcFlags := req.ReqBody.KdcOptions.Data
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
		Nonce:         req.ReqBody.NoOnce,
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

func princNotFoundError(req datamodel.AsReq, name datamodel.PrincipalName) datamodel.KrbError {
	ctime := time.Now()
	return datamodel.KrbError{
		CTime:     datamodel.KerberosTime{ctime.Unix()},
		CUSec:     int32(ctime.Nanosecond() / 1000),
		ErrorCode: datamodel.KDC_ERR_C_PRINCIPAL_UNKNOWN,
		CRealm:    req.ReqBody.Realm,
		SName:     *req.ReqBody.SName,
		EText:     fmt.Sprintf("Principal %s not found", datamodel.JoinPrinc(name, req.ReqBody.Realm)),
		EData:     make([]byte, 0),
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
	postdated := req.ReqBody.KdcOptions.Data[datamodel.KDC_FLAG_POSTDATED]
	if postdated && difference < a.clockSkew {
		return noError(), now, false
	}
	if !postdated && difference > a.clockSkew {
		err := newEmptyError(req)
		err.ErrorCode = datamodel.KDC_ERR_CANNOT_POSTDATE
		return err, datamodel.KerberosTime{}, false
	}
	// check against policy
	if postdated && difference > a.maxPostdate {
		err := newEmptyError(req)
		err.ErrorCode = datamodel.KDC_ERR_CANNOT_POSTDATE
		return err, datamodel.KerberosTime{}, false
	}
	// postdated ticket beyond clock skew clock skew or non-postdated within clock skew
	return noError(), *req.ReqBody.From, true

}

func getExpirationTime(
	realmExpirationTime int64,
	princExpirationTime int64,
	startTime datamodel.KerberosTime,
	requestedTill datamodel.KerberosTime) datamodel.KerberosTime {

	maxExpiration := min64(princExpirationTime, realmExpirationTime)
	enforced := min64(requestedTill.Timestamp, startTime.Timestamp+maxExpiration)
	return datamodel.KerberosTime{Timestamp: enforced}
}

// TODO
func (a *authenticationServer) preauthCheck(req datamodel.AsReq) (ok bool, err datamodel.KrbError) {
	return ok, noError()
}

func (a *authenticationServer) generateSessionKey(algo crypto.Algorithm) datamodel.EncryptionKey {
	keyData := algo.GenerateKey()
	return datamodel.EncryptionKey{KeyType: algo.EType(), KeyValue: keyData}
}

func newEmptyError(req datamodel.AsReq) datamodel.KrbError {
	ctime, usec := kerberosNow()
	return datamodel.KrbError{
		CTime: ctime,
		CUSec: usec,
		//ErrorCode: ,
		CRealm: req.ReqBody.Realm,
		SName:  *req.ReqBody.SName,
		//EText:     ,
		//EData:     make([]byte, 0),
	}
}

func (a *authenticationServer) checkMinLifetime(req datamodel.AsReq, startTime datamodel.KerberosTime, expirationTime datamodel.KerberosTime) (bool, datamodel.KrbError) {
	if expirationTime.Timestamp-startTime.Timestamp < a.minTicketLifetime {
		err := newEmptyError(req)
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

func noError() datamodel.KrbError {
	return datamodel.KrbError{}
}

func noRep() datamodel.AsRep {
	return datamodel.AsRep{}
}

func kerberosNow() (t datamodel.KerberosTime, usec int32) {
	return datamodel.KerberosTimeNow()
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
