package appsrv

import (
	"github.com/chemikadze/gorberos/crypto"
	"github.com/chemikadze/gorberos/datamodel"
)

type ApplicationServer interface {
	ApplicationServerExchange(datamodel.ApReq) (ok bool, err datamodel.KrbError, rep datamodel.ApReq)
}

type applicationServer struct {
	crypto       crypto.EncryptionFactory
	clockSkew    int64
	principal    datamodel.PrincipalName
	defaultRealm datamodel.Realm
	realmKeys    map[datamodel.Realm]datamodel.EncryptionKey
	tgts         map[datamodel.Realm]datamodel.Ticket
	tgtKeys      map[datamodel.Realm]datamodel.EncryptionKey
	recvSeqNo    *uint32
	sendSeqNo    *uint32
	subKey       *datamodel.EncryptionKey
	seqNoEnabled bool
}

func (a *applicationServer) ApplicationServerExchange(req datamodel.ApReq) (ok bool, kerr datamodel.KrbError, krep datamodel.ApRep) {
	if req.MsgType != datamodel.MSG_TYPE_KRB_AP_REQ {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_MSG_TYPE), noRep()
	}
	if req.Ticket.VNo < 5 {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_BADKEYVER), noRep()
	}
	// ticket is encrypted in the session key from the server's TGT rather server's secret key
	useSessionKey := req.ApOptions[datamodel.AP_FLAG_USE_SESSION_KEY]
	ticketFound, ticketKey := a.pickKey(req.Ticket.Realm, useSessionKey)
	if !ticketFound {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_NOKEY), noRep()
	}
	ticket := datamodel.EncTicketPart{}
	err := a.decrypt(req.Ticket.EncPart, ticketKey, &ticket)
	if err != nil {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_BAD_INTEGRITY), noRep()
	}

	auth := datamodel.Authenticator{}
	err = a.decrypt(req.Authenticator, ticket.Key, &auth)
	if err != nil {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_BAD_INTEGRITY), noRep()
	}
	if !auth.CName.Equal(ticket.CName) || auth.CRealm != ticket.CRealm {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_BADMATCH), noRep()
	}

	// TODO client address verification -- should be part of arguments?
	// If no match is found or the server insists on ticket addresses
	// but none are present in the ticket, the KRB_AP_ERR_BADADDR error is returned

	stime, _ := datamodel.KerberosTimeNow()
	if auth.CTime.AbsoluteDifference(stime) > a.clockSkew {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_SKEW), noRep()
	}

	if a.checkReplayAttack(auth) {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_REPEAT), noRep()
	}

	a.recvSeqNo = auth.SeqNumber
	a.subKey = auth.SubKey

	if ticket.StartTime != nil && ticket.StartTime.Difference(stime) > a.clockSkew ||
		ticket.Flags[datamodel.TKT_FLAG_INVALID] {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_TKT_NYV), noRep()
	}
	if ticket.EndTime.Difference(stime) > a.clockSkew {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_TKT_EXPIRED), noRep()
	}
	// end of ticket validations, server is assured that client is authenticated

	if !req.ApOptions[datamodel.AP_FLAG_MUTUAL_REQUIRED] {
		if a.seqNoEnabled {
			seqNo := crypto.GenerateSeqNumber()
			a.sendSeqNo = &seqNo
		}
		//  implementations ... MAY provide routines to choose subkeys based on session keys
		var subKey *datamodel.EncryptionKey = nil
		rep := datamodel.EncAPRepPart{
			CTime:     auth.CTime,
			CUSec:     auth.CUSec,
			SubKey:    subKey,
			SeqNumber: a.sendSeqNo,
		}
		err, encRepData := a.encrypt(ticket.Key, rep)
		if err != nil {
			return
		}
		return true, datamodel.NoError(), datamodel.ApRep{EncPart: encRepData}
	}
	return true, datamodel.NoError(), noRep()
}

func (a *applicationServer) pickKey(realm datamodel.Realm, useSessionKey bool) (bool, datamodel.EncryptionKey) {
	if useSessionKey {
		tgtKey, keyFound := a.tgtKeys[realm]
		if !keyFound {
			return false, datamodel.EncryptionKey{}
		} else {
			return true, tgtKey
		}
	} else {
		serverKey, keyFound := a.realmKeys[realm]
		if !keyFound {
			return false, datamodel.EncryptionKey{}
		} else {
			return true, serverKey
		}
	}
}

func noRep() datamodel.ApRep {
	return datamodel.ApRep{}
}

func (a *applicationServer) decrypt(input datamodel.EncryptedData, key datamodel.EncryptionKey, dest interface{}) error {
	algo := a.crypto.Create(key.KeyType)
	return algo.Decrypt(input, key, dest)
}

func (a *applicationServer) encrypt(key datamodel.EncryptionKey, input interface{}) (error, datamodel.EncryptedData) {
	algo := a.crypto.Create(key.KeyType)
	return algo.Encrypt(key, input)
}

func (a *applicationServer) checkReplayAttack(datamodel.Authenticator) bool {
	// TODO implement
	//replay cache will store at least the server name, along with the
	//client name, time, and microsecond fields from the recently-seen
	//authenticators

	//If a server loses track of authenticators presented within the
	//allowable clock skew, it MUST reject all requests until the clock
	//skew interval has passed,

	return false
}
