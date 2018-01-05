package appsrv

import (
	"github.com/chemikadze/gorberos/crypto"
	"github.com/chemikadze/gorberos/datamodel"
)

type ApplicationServer interface {
	ApplicationServerExchange(datamodel.AP_REQ) (ok bool, err datamodel.KRB_ERROR, rep datamodel.AP_REP)
}

type applicationServer struct {
	crypto       crypto.EncryptionFactory
	clockSkew    int64
	principal    datamodel.PrincipalName
	defaultRealm datamodel.Realm
	realmKeys    map[datamodel.Realm]datamodel.EncryptionKey
	tgts         map[datamodel.Realm]datamodel.Ticket
	tgtKeys      map[datamodel.Realm]datamodel.EncryptionKey
	recvSeqNo    *datamodel.UInt32
	sendSeqNo    datamodel.UInt32
	subKey       *datamodel.EncryptionKey
	seqNoEnabled bool
}

func (a *applicationServer) ApplicationServerExchange(req datamodel.AP_REQ) (ok bool, kerr datamodel.KRB_ERROR, krep datamodel.AP_REP) {
	if req.Msg_type != datamodel.MSG_TYPE_KRB_AP_REQ {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_MSG_TYPE), noRep()
	}
	if req.Ticket.Tkt_vno < 5 {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_BADKEYVER), noRep()
	}
	// ticket is encrypted in the session key from the server's TGT rather server's secret key
	reqApOptions := datamodel.APOptions(req.Ap_options)
	useSessionKey := reqApOptions.Get(datamodel.AP_FLAG_USE_SESSION_KEY)
	ticketFound, ticketKey := a.pickKey(req.Ticket.Realm, useSessionKey)
	if !ticketFound {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_NOKEY), noRep()
	}
	ticket := datamodel.EncTicketPart{}
	err := a.decrypt(req.Ticket.Enc_part, ticketKey, &ticket)
	if err != nil {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_BAD_INTEGRITY), noRep()
	}

	auth := datamodel.Authenticator{}
	err = a.decrypt(req.Authenticator, ticket.Key, &auth)
	if err != nil {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_BAD_INTEGRITY), noRep()
	}
	if !auth.Cname.Equal(ticket.Cname) || auth.Crealm != ticket.Crealm {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_BADMATCH), noRep()
	}

	// TODO client address verification -- should be part of arguments?
	// If no match is found or the server insists on ticket addresses
	// but none are present in the ticket, the KRB_AP_ERR_BADADDR error is returned

	stime, _ := datamodel.KerberosTimeNowUsec()
	if datamodel.KerberosTime(auth.Ctime).AbsoluteDifference(stime) > a.clockSkew {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_SKEW), noRep()
	}

	if a.checkReplayAttack(auth) {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_REPEAT), noRep()
	}

	a.recvSeqNo = &auth.Seq_number
	a.subKey = &auth.Subkey

	ticketStartTime := datamodel.KerberosTime(ticket.Starttime)
	ticketEndTime := datamodel.KerberosTime(ticket.Endtime)
	ticketFlags := datamodel.TicketFlags(ticket.Flags)
	if !ticketStartTime.IsEmpty() && ticketStartTime.Difference(stime) > a.clockSkew ||
		ticketFlags.Get(datamodel.TKT_FLAG_INVALID) {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_TKT_NYV), noRep()
	}
	if ticketEndTime.Difference(stime) > a.clockSkew {
		return false, datamodel.NewErrorC(a.defaultRealm, a.principal, datamodel.KRB_AP_ERR_TKT_EXPIRED), noRep()
	}
	// end of ticket validations, server is assured that client is authenticated

	if !reqApOptions.Get(datamodel.AP_FLAG_MUTUAL_REQUIRED) {
		if a.seqNoEnabled {
			seqNo := crypto.GenerateSeqNumber()
			a.sendSeqNo = datamodel.UInt32(seqNo)
		}
		//  implementations ... MAY provide routines to choose subkeys based on session keys
		var subKey datamodel.EncryptionKey
		rep := datamodel.EncAPRepPart{
			Ctime:     auth.Ctime,
			Cusec:     auth.Cusec,
			Subkey:    subKey,
			Seq_number: a.sendSeqNo,
		}
		err, encRepData := a.encrypt(ticket.Key, rep)
		if err != nil {
			return
		}
		return true, datamodel.NoError(), datamodel.AP_REP{Enc_part: encRepData}
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

func noRep() datamodel.AP_REP {
	return datamodel.AP_REP{}
}

func (a *applicationServer) decrypt(input datamodel.EncryptedData, key datamodel.EncryptionKey, dest interface{}) error {
	algo := a.crypto.Create(key.Keytype)
	return algo.Decrypt(input, key, dest)
}

func (a *applicationServer) encrypt(key datamodel.EncryptionKey, input interface{}) (error, datamodel.EncryptedData) {
	algo := a.crypto.Create(key.Keytype)
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
