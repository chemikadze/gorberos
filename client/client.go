package client

import (
	"errors"
	"fmt"
	"github.com/chemikadze/gorberos"
	"github.com/chemikadze/gorberos/crypto"
	"github.com/chemikadze/gorberos/datamodel"
	"time"
)

type client struct {
	transport       gorberos.ClientTransport
	tgt             datamodel.Ticket
	encAsRep        datamodel.EncAsRepPart
	cname           datamodel.PrincipalName
	sname           datamodel.PrincipalName
	realm           datamodel.Realm
	encFactory      crypto.EncryptionFactory
	cksumFactory    crypto.ChecksumFactory
	keyLifetime     *uint32
	key             datamodel.EncryptionKey
	appTicket       datamodel.Ticket
	appEncTicket    datamodel.EncTGSRepPart
	apUseSessionKey bool
	apMutualAuth    bool
	seqNum          uint32
	subKey          datamodel.EncryptionKey
}

type SessionParams struct {
	CName datamodel.PrincipalName
	SName datamodel.PrincipalName
	Realm datamodel.Realm
}

func New(transport gorberos.ClientTransport, encFactory crypto.Factory, params SessionParams) gorberos.Client {
	c := client{
		transport:  transport,
		encFactory: encFactory,
		cksumFactory: encFactory,
		cname:      params.CName,
		sname:      params.SName,
		realm:      params.Realm,
	}
	return &c
}

func (c *client) Authenticate() error {
	nonce := crypto.GenerateNonce()
	var till int64
	if c.keyLifetime != nil {
		till = time.Now().Unix() + int64(*c.keyLifetime)
	}
	flags := datamodel.NewKdcOptions()
	req := datamodel.AsReq{
		ReqBody: datamodel.KdcReqBody{
			KdcOptions: flags,
			CName:      &c.cname,
			SName:      &c.sname,
			Realm:      c.realm,
			Till:       datamodel.KerberosTime{till},
			Nonce:      nonce,
			EType:      c.encFactory.SupportedETypes(),
		},
	}
	err, rep := c.transport.SendAsReq(req)
	if err != nil {
		return err
	}
	err = c.validateKdcRep(datamodel.KdcReq(req), datamodel.KdcRep(rep))
	if err != nil {
		return err
	}

	encRep := datamodel.EncAsRepPart{}
	err = c.decrypt(c.key, rep.EncPart, &encRep)
	if err != nil {
		return err
	}
	err = c.validateEncKdcRepPart(datamodel.KdcReq(req), datamodel.EncKDCRepPart(encRep))
	if err != nil {
		return err
	}

	// TODO authtime can be used to adjust subsequent messages
	c.tgt = rep.Ticket
	c.encAsRep = encRep

	return nil
}

/**

  When:
   1) obtain auth creedentials (using TGT ticket)
   2) renew or validate ticket
   3) obtain proxy ticket

  The primary difference is that encryption and
  decryption in the TGS exchange does not take place under the client's
  key.  Instead, the session key from the TGT or renewable ticket, or
  sub-session key from an Authenticator is used.
*/
func (c *client) AuthenticateTgs() error {
	flags := datamodel.NewKdcOptions()
	nonce := crypto.GenerateNonce()
	till := datamodel.KerberosEpoch()
	if c.keyLifetime != nil {
		t := time.Now().Unix() + int64(*c.keyLifetime)
		till = datamodel.KerberosTime{Timestamp: t}
	}
	reqBody := datamodel.KdcReqBody{
		KdcOptions: flags,
		Realm:      c.realm,
		SName:      &c.sname, // TODO may be absent in ENC-TKT-IN-SKEY case
		Till:       till,
		Nonce:      nonce,
		EType:      c.encFactory.SupportedETypes(),
	}
	cksum := c.computeChecksum(reqBody)
	auth := c.generateAuthenticator(&cksum)
	err, apReq := c.generateApReq(auth)
	if err != nil {
		return err
	}
	paReq := datamodel.PaTgsReq(apReq)
	paData := []datamodel.PaData{{Value: paReq}} // TODO other padata fields
	req := datamodel.TgsReq{
		PaData:  paData,
		ReqBody: reqBody,
	}

	err, rep := c.transport.SendTgsReq(req)
	if err != nil {
		return err
	}
	// TODO this does not seem right
	//err = c.validateKdcRep(datamodel.KdcReq(req), datamodel.KdcRep(rep))
	//if err != nil {
	//	return err
	//}

	encRep := datamodel.EncTGSRepPart{}
	err = c.decrypt(c.encAsRep.Key, rep.EncPart, &encRep)
	if err != nil {
		return err
	}
	err = c.validateEncKdcRepPart(datamodel.KdcReq(req), datamodel.EncKDCRepPart(encRep))
	if err != nil {
		return err
	}

	c.appTicket = rep.Ticket
	c.appEncTicket = encRep

	return nil
}

func (c *client) AuthenticateApplication() error {
	var key datamodel.EncryptionKey
	key = c.appEncTicket.Key
	auth := c.generateAuthenticator(nil)
	err, req := c.generateApReq(auth)
	if err != nil {
		return err
	}
	err, rep := c.transport.SendApReq(req)
	if err != nil {
		return err
	}
	encApRep := datamodel.EncAPRepPart{}
	err = c.decrypt(key, rep.EncPart, &encApRep)
	if err != nil {
		return nil
	}
	if encApRep.CTime != auth.CTime || encApRep.CUSec != auth.CUSec {
		return errors.New(fmt.Sprintf(
			"Response CTime or CUSec did not match those of authenticator: %v != %v || %v != %v ",
			encApRep.CTime, auth.CTime, encApRep.CUSec, auth.CUSec))
	}
	if encApRep.SeqNumber != nil {
		c.seqNum = *encApRep.SeqNumber
	}
	//  implementations ... MAY provide routines to choose subkeys based on session keys
	if encApRep.SubKey != nil {
		c.subKey = *encApRep.SubKey
	}
	return nil
}

func (c *client) generateApReq(auth datamodel.Authenticator) (error, datamodel.ApReq) {
	flags := datamodel.NewApOptions()
	flags[datamodel.AP_FLAG_USE_SESSION_KEY] = c.apUseSessionKey
	flags[datamodel.AP_FLAG_MUTUAL_REQUIRED] = c.apMutualAuth
	err, encAuth := c.encryptAuthenticator(c.encAsRep.Key, auth)
	if err != nil {
		return err, datamodel.ApReq{}
	}
	return nil, datamodel.ApReq{
		ApOptions:     flags,
		Ticket:        c.tgt,
		Authenticator: encAuth,
	}
}

func (c *client) validateKdcRep(req datamodel.KdcReq, rep datamodel.KdcRep) error {
	if !rep.CName.Equal(*req.ReqBody.CName) {
		return errors.New(fmt.Sprintf(
			"Response cname %v does not match request cname %v", rep.CName, req.ReqBody.CName))
	}
	if rep.CRealm != req.ReqBody.Realm {
		return errors.New(fmt.Sprintf(
			"Response crealm %v does not match request realm %v", rep.CRealm, req.ReqBody.Realm))
	}
	return nil
}

func (c *client) validateEncKdcRepPart(req datamodel.KdcReq, encRep datamodel.EncKDCRepPart) error {
	if encRep.Nonce != req.ReqBody.Nonce {
		return errors.New("Potential replay attack: nonce of KRB_AS_REP did not match nonce of KRB_AS_REQ")
	}
	// TODO padata
	if req.ReqBody.SName != nil && !encRep.SName.Equal(*req.ReqBody.SName) {
		return errors.New(fmt.Sprintf(
			"Response sname %v does not match request cname %v", req.ReqBody.SName, encRep.SName))
	}
	if encRep.SRealm != req.ReqBody.Realm {
		return errors.New(fmt.Sprintf(
			"Response srealm %v does not match request realm %v", encRep.SRealm, req.ReqBody.Realm))
	}
	return nil
}

func (c *client) decrypt(key datamodel.EncryptionKey, data datamodel.EncryptedData, dest interface{}) error {
	algorithm := c.encFactory.Create(data.EType)
	return algorithm.Decrypt(data, key, dest)
}

func (c *client) computeChecksum(reqBody datamodel.KdcReqBody) datamodel.Checksum {
	key := c.encAsRep.Key
	ckType := c.cksumFactory.ChecksumTypeForEncryption(key.KeyType)
	ckAlgo := c.cksumFactory.CreateChecksum(ckType)
	data := make([]byte, 0) // TODO serialize
	mic := ckAlgo.GetMic(key, data)
	return datamodel.Checksum{ckType, mic}
}

func (c *client) generateAuthenticator(cksum *datamodel.Checksum) datamodel.Authenticator {
	// TODO Client implementations SHOULD ensure that the timestamps are not reused
	ctime, usec := datamodel.KerberosTimeNowUsec()
	return datamodel.Authenticator{
		AuthenticatorVNo:  5,
		CRealm:            c.realm,
		CName:             c.cname,
		CKSum:             cksum,
		CUSec:             usec,
		CTime:             ctime,
		SubKey:            nil, // session key from ticket will be used
		SeqNumber:         nil, // TODO support of seq numbers to detect replays
		AuthorizationData: nil, // additional restrictions ontop of specified in a ticket
	}
}

func (c *client) encryptAuthenticator(key datamodel.EncryptionKey, auth datamodel.Authenticator) (error, datamodel.EncryptedData) {
	algorithm := c.encFactory.Create(key.KeyType)
	return algorithm.Encrypt(key, auth)
}
