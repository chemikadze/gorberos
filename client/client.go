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
	serializer      datamodel.Serializer
	encAsRep        datamodel.EncASRepPart
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
	seqNum          datamodel.UInt32
	subKey          datamodel.EncryptionKey
}

type SessionParams struct {
	CName datamodel.PrincipalName
	SName datamodel.PrincipalName
	Realm datamodel.Realm
}

func New(transport gorberos.ClientTransport, encFactory crypto.Factory, params SessionParams) gorberos.Client {
	c := client{
		transport:    transport,
		serializer:   datamodel.NewSerializer(),
		encFactory:   encFactory,
		cksumFactory: encFactory,
		cname:        params.CName,
		sname:        params.SName,
		realm:        params.Realm,
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
	krbTgt := datamodel.KrbTgtForRealm(c.realm)
	req := datamodel.AS_REQ{
		Req_body: datamodel.KDC_REQ_BODY{
			Kdc_options: flags.ToWire(),
			Cname:      c.cname,
			Sname:      krbTgt,
			Realm:      c.realm,
			Till:       datamodel.KerberosTimeFromUnix(till).ToWire(),
			Nonce:      datamodel.UInt32(nonce),
			Etype:      c.encFactory.SupportedETypes(),
		},
	}
	err, rep := c.transport.SendAsReq(req)
	if err != nil {
		return err
	}
	err = c.validateKdcRep(datamodel.KDC_REQ(req), datamodel.KDC_REP(rep))
	if err != nil {
		return err
	}

	var encRep datamodel.EncASRepPart
	err = c.decrypt(c.key, rep.Enc_part, &encRep)
	if err != nil {
		return err
	}
	err = c.validateEncKdcRepPart(datamodel.KDC_REQ(req), datamodel.EncKDCRepPart(encRep))
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
		till = datamodel.KerberosTimeFromUnix(t)
	}
	reqBody := datamodel.KDC_REQ_BODY{
		Kdc_options: flags.ToWire(),
		Realm:      c.realm,
		Sname:      c.sname, // TODO may be absent in ENC-TKT-IN-SKEY case
		Till:       till.ToWire(),
		Nonce:      datamodel.UInt32(nonce),
		Etype:      c.encFactory.SupportedETypes(),
	}
	cksum := c.computeChecksum(reqBody)
	auth := c.generateAuthenticator(cksum)
	err, apReq := c.generateApReq(auth)
	if err != nil {
		return err
	}
	apReqBytes, err := c.serializer.Marshal(apReq)
	if err != nil {
		return err
	}
	paReq := datamodel.PA_DATA{datamodel.PA_T_TGS_REQ, apReqBytes}
	paData := []datamodel.PA_DATA{paReq} // TODO other padata fields
	req := datamodel.TGS_REQ{
		Padata:  paData,
		Req_body: reqBody,
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
	err = c.decrypt(c.encAsRep.Key, rep.Enc_part, &encRep)
	if err != nil {
		return err
	}
	err = c.validateEncKdcRepPart(datamodel.KDC_REQ(req), datamodel.EncKDCRepPart(encRep))
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
	auth := c.generateAuthenticator(datamodel.Checksum{})
	err, req := c.generateApReq(auth)
	if err != nil {
		return err
	}
	err, rep := c.transport.SendApReq(req)
	if err != nil {
		return err
	}
	encApRep := datamodel.EncAPRepPart{}
	err = c.decrypt(key, rep.Enc_part, &encApRep)
	if err != nil {
		return nil
	}
	if encApRep.Ctime != auth.Ctime || encApRep.Cusec != auth.Cusec {
		return errors.New(fmt.Sprintf(
			"Response CTime or CUSec did not match those of authenticator: %v != %v || %v != %v ",
			encApRep.Ctime, auth.Ctime, encApRep.Cusec, auth.Cusec))
	}
	if encApRep.Seq_number != 0 {
		c.seqNum = encApRep.Seq_number
	}
	//  implementations ... MAY provide routines to choose subkeys based on session keys
	if !encApRep.Subkey.IsEmpty() {
		c.subKey = encApRep.Subkey
	}
	return nil
}

func (c *client) generateApReq(auth datamodel.Authenticator) (error, datamodel.AP_REQ) {
	flags := datamodel.NewApOptions()
	flags.Set(datamodel.AP_FLAG_USE_SESSION_KEY, c.apUseSessionKey)
	flags.Set(datamodel.AP_FLAG_MUTUAL_REQUIRED, c.apMutualAuth)
	err, encAuth := c.encryptAuthenticator(c.encAsRep.Key, auth)
	if err != nil {
		return err, datamodel.AP_REQ{}
	}
	return nil, datamodel.AP_REQ{
		Ap_options:     flags.ToWire(),
		Ticket:        c.tgt,
		Authenticator: encAuth,
	}
}

func (c *client) validateKdcRep(req datamodel.KDC_REQ, rep datamodel.KDC_REP) error {
	if !rep.Cname.Equal(req.Req_body.Cname) {
		return errors.New(fmt.Sprintf(
			"Response cname '%v' does not match request cname '%v'", rep.Cname, req.Req_body.Cname))
	}
	if rep.Crealm != req.Req_body.Realm {
		return errors.New(fmt.Sprintf(
			"Response crealm '%v' does not match request realm '%v'", rep.Crealm, req.Req_body.Realm))
	}
	return nil
}

func (c *client) validateEncKdcRepPart(req datamodel.KDC_REQ, encRep datamodel.EncKDCRepPart) error {
	if encRep.Nonce != req.Req_body.Nonce {
		return errors.New("Potential replay attack: nonce of KRB_AS_REP did not match nonce of KRB_AS_REQ")
	}
	// TODO padata
	if !req.Req_body.Sname.IsEmpty() && !encRep.Sname.Equal(req.Req_body.Sname) {
		return errors.New(fmt.Sprintf(
			"Response sname '%v' does not match request sname '%v'", encRep.Sname, req.Req_body.Sname))
	}
	if encRep.Srealm != req.Req_body.Realm {
		return errors.New(fmt.Sprintf(
			"Response srealm '%v' does not match request realm '%v'", encRep.Srealm, req.Req_body.Realm))
	}
	return nil
}

func (c *client) decrypt(key datamodel.EncryptionKey, data datamodel.EncryptedData, dest interface{}) error {
	algorithm := c.encFactory.Create(data.Etype)
	return algorithm.Decrypt(data, key, dest)
}

func (c *client) computeChecksum(reqBody datamodel.KDC_REQ_BODY) datamodel.Checksum {
	key := c.encAsRep.Key
	ckType := c.cksumFactory.ChecksumTypeForEncryption(key.Keytype)
	ckAlgo := c.cksumFactory.CreateChecksum(ckType)
	data := make([]byte, 0) // TODO serialize
	mic := ckAlgo.GetMic(key, data)
	return datamodel.Checksum{ckType, mic}
}

func (c *client) generateAuthenticator(cksum datamodel.Checksum) datamodel.Authenticator {
	// TODO Client implementations SHOULD ensure that the timestamps are not reused
	ctime, usec := datamodel.KerberosTimeNowUsec()
	return datamodel.Authenticator{
		Authenticator_vno:  5,
		Crealm:            c.realm,
		Cname:             c.cname,
		Cksum:             cksum,
		Cusec:             datamodel.Microseconds(usec),
		Ctime:             ctime.ToWire(),
		//Subkey:            nil, // session key from ticket will be used
		//Seq_number:         nil, // TODO support of seq numbers to detect replays
		//Authorization_data: nil, // additional restrictions ontop of specified in a ticket
	}
}

func (c *client) encryptAuthenticator(key datamodel.EncryptionKey, auth datamodel.Authenticator) (error, datamodel.EncryptedData) {
	algorithm := c.encFactory.Create(key.Keytype)
	return algorithm.Encrypt(key, auth)
}
