package asrv

import (
	"fmt"
	"github.com/chemikadze/gorberos/crypto"
	"github.com/chemikadze/gorberos/database"
	"github.com/chemikadze/gorberos/datamodel"
	"time"
)

type AuthenticationServer interface {
	AuthenticationServerExchange(datamodel.AsReq) (ok bool, err datamodel.KrbError, rep datamodel.AsRep)
}

type authenticationServer struct {
	database          database.KdcDatabase
	crypto            crypto.Factory
	clockSkew         int64
	minTicketLifetime int64
	maxRenewTime      int64
	realm             datamodel.Realm
}

func (a *authenticationServer) AuthenticationServerExchange(req datamodel.AsReq) (ok bool, err datamodel.KrbError, rep datamodel.AsRep) {
	clientPrinc, ok := a.database.GetPrincipal(req.ReqBody.CName)
	if !ok {
		return false, princNotFoundError(req, req.ReqBody.CName), noRep()
	}
	serverPrinc, ok := a.database.GetPrincipal(*(req.ReqBody.SName)) // TODO when it is null?
	if !ok {
		return false, princNotFoundError(req, *(req.ReqBody.SName)), noRep()
	}
	if ok, err := a.preauthCheck(req); !ok {
		return false, err, noRep()
	}
	if !a.checkEtypes(req.ReqBody.EType) {
		return false, algorithmNotFoundError(req), noRep()
	}
	ok, clientKey := a.getSupportedKey(req.ReqBody.EType, clientPrinc.SecretKeys)
	sessionAlgo := a.selectSessionKeyAlgo(req.ReqBody.EType)
	sessionKey := a.generateSessionKey(sessionAlgo)
	// TODO support POSTDATE
	ok, err, startTime := a.getStarttime(req)
	if !ok {
		return false, err, noRep()
	}
	expirationTime := a.getExpirationTime(startTime, clientPrinc, req.ReqBody.Till)
	if ok, err := a.checkMinLifetime(req, startTime, expirationTime); !ok {
		return false, err, noRep()
	}
	renewable := req.ReqBody.KdcOptions.Data[datamodel.KDC_FLAG_RENEWABLE_OK]
	var renewTill *datamodel.KerberosTime
	if renewable {
		renew := a.calcNextRenewTill(clientPrinc, serverPrinc, req.ReqBody.RTime)
		renewTill = &renew
	}
	encTicket := datamodel.EncTicketPart{
		//Flags             TicketFlags // TODO set FORWARDABLE, MAY-POSTDATE, POSTDATED, PROXIABLE, RENEWABLE
		//Key TODO???
		CRealm: req.ReqBody.Realm,
		CName:  req.ReqBody.CName,
		//Transited         TransitedEncoding
		AuthTime:  datamodel.KerberosTime{time.Now().Unix()},
		StartTime: &startTime,
		EndTime:   expirationTime,
		RenewTill: renewTill,
		CAddr:     req.ReqBody.Addresses,
		//AuthorizationData AuthorizationData
	}
	ticket := datamodel.Ticket{
		Realm:   a.realm,
		SName:   *(req.ReqBody.SName), // TODO AS or what?
		EncPart: a.encryptTicketPart(serverPrinc.SecretKeys, encTicket),
	}
	encAsRep := datamodel.EncAsRepPart{
		Key: sessionKey,
		LastReq: make(datamodel.LastReq, 0), //TODO
		NoNCE:         req.ReqBody.NoOnce,
		KeyExpiration: &expirationTime,
		//Flags         TicketFlags TODO
		AuthTime:  datamodel.KerberosTime{time.Now().Unix()},
		StartTime: &startTime,
		EndTime:   expirationTime,
		RenewTill: renewTill,
		SRealm:    a.realm,
		SName:     *(req.ReqBody.SName),
		CAddr:     req.ReqBody.Addresses,
	}
	rep = datamodel.AsRep{
		PaData:  make([]datamodel.PaData, 0), // TODO
		CRealm:  req.ReqBody.Realm,
		CName:   req.ReqBody.CName,
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
		SName:     *(req.ReqBody.SName),
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

func isSupportedEtype(factory crypto.Factory, requested int32) bool {
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
		SName:     *(req.ReqBody.SName),
		EText:     "Neither of requested encryption types is supported",
	}
}

func (a *authenticationServer) getStarttime(req datamodel.AsReq) (bool, datamodel.KrbError, datamodel.KerberosTime) {
	if req.ReqBody.RTime == nil {
		return true, noError(), datamodel.KerberosTime{time.Now().Unix()}
	}
	difference := req.ReqBody.RTime.Timestamp - time.Now().Unix() // -past, +future
	if difference < 0 {
		return true, noError(), datamodel.KerberosTime{time.Now().Unix()}
	}
	postdated := req.ReqBody.KdcOptions.Data[datamodel.KDC_FLAG_POSTDATED]
	if postdated && difference < a.clockSkew {
		return true, noError(), datamodel.KerberosTime{time.Now().Unix()}
	}
	if !postdated && difference > a.clockSkew {
		err := newEmptyError(req)
		err.ErrorCode = datamodel.KDC_ERR_CANNOT_POSTDATE
		return false, err, datamodel.KerberosTime{}
	}
	// postdated ticket beyond clock skew clock skew or non-postdated within clock skew
	// TODO checked against the policy of the local realm
	// TODO set INVALID flag on ticket
	return true, noError(), *(req.ReqBody.RTime) // todo when rtime is not nil?

}

func (a *authenticationServer) getExpirationTime(startTime datamodel.KerberosTime, princ database.PrincipalInfo,
	requestedTill datamodel.KerberosTime) datamodel.KerberosTime {
	// TODO enforce local and principal policy
	return requestedTill
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
		SName:  *(req.ReqBody.SName),
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
	now := time.Now()
	return datamodel.KerberosTime{now.Unix()}, int32(now.Nanosecond() / 1000)
}