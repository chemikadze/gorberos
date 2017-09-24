package client

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/chemikadze/gorberos"
	"github.com/chemikadze/gorberos/crypto"
	"github.com/chemikadze/gorberos/datamodel"
	"math"
	"math/big"
	"time"
)

type client struct {
	transport       gorberos.ClientTransport
	tgt             datamodel.Ticket
	cname           datamodel.PrincipalName
	sname           datamodel.PrincipalName
	realm           datamodel.Realm
	encFactory      crypto.EncryptionFactory
	cksumFactory    crypto.ChecksumFactory
	keyLifetime     *uint32
	key             datamodel.EncryptionKey
	sessionKey      datamodel.EncryptionKey
	keyStartTime    *datamodel.KerberosTime
	keyEndTime      datamodel.KerberosTime
	apUseSessionKey bool
	apMutualAuth    bool
	seqNum          uint32
	subKey          datamodel.EncryptionKey
}

func New(transport gorberos.ClientTransport) gorberos.Client {
	return client{
		transport: transport,
	}
}

func (c client) Authenticate() error {
	n, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	nonce := uint32(n.Uint64())
	var till int64
	if c.keyLifetime != nil {
		till = time.Now().Unix() + int64(*c.keyLifetime)
	}
	req := datamodel.AsReq{
		ReqBody: datamodel.KdcReqBody{
			KdcOptions: datamodel.KdcOptions{}, // TODO
			CName:      c.cname,
			Realm:      c.realm,
			Till:       datamodel.KerberosTime{till},
			NoOnce:     nonce,
			EType:      c.encFactory.SupportedETypes(),
		},
	}
	err, rep := c.transport.SendAsReq(req)
	if err != nil {
		return err
	}
	if !rep.CName.Equal(req.ReqBody.CName) {
		return errors.New(fmt.Sprintf(
			"Response cname %v does not match request cname %v", rep.CName, req.ReqBody.CName))
	}
	if rep.CRealm != req.ReqBody.Realm {
		return errors.New(fmt.Sprintf(
			"Response crealm %v does not match request realm %v", rep.CRealm, req.ReqBody.Realm))
	}
	// The encrypted part of the KRB_AS_REP message also contains the nonce
	// that MUST be matched with the nonce from the KRB_AS_REQ message.
	encRep := datamodel.EncAsRepPart{}
	err = c.decrypt(rep.EncPart, &encRep)
	if err != nil {
		return err
	}
	if encRep.Nonce != nonce {
		return errors.New("Potential replay attack: nonce of KRB_AS_REP did not match nonce of KRB_AS_REQ")
	}
	// TODO padata
	if req.ReqBody.SName != nil && !encRep.SName.Equal(*req.ReqBody.SName) {
		return errors.New(fmt.Sprintf(
			"Response sname %v does not match request cname %v", rep.CName, req.ReqBody.CName))
	}
	if encRep.SRealm != req.ReqBody.Realm {
		return errors.New(fmt.Sprintf(
			"Response srealm %v does not match request realm %v", rep.CRealm, req.ReqBody.Realm))
	}
	// TODO authtime can be used to adjust subsequent messages
	c.tgt = rep.Ticket
	c.sessionKey = encRep.Key
	c.keyStartTime = encRep.StartTime
	c.keyEndTime = encRep.EndTime

	return nil
}

func (c client) AuthenticateApplication() error {
	flags := datamodel.NewApOptions()
	flags[datamodel.AP_FLAG_USE_SESSION_KEY] = c.apUseSessionKey
	flags[datamodel.AP_FLAG_MUTUAL_REQUIRED] = c.apMutualAuth
	auth := c.generateAuthenticator()
	err, encAuth := c.encryptAuthenticator(c.sessionKey, auth)
	if err != nil {
		return err
	}
	req := datamodel.ApReq{
		ApOptions:     flags,
		Ticket:        c.tgt,
		Authenticator: encAuth,
	}
	err, rep := c.transport.SendApReq(req)
	if err != nil {
		return err
	}
	encApRep := datamodel.EncAPRepPart{}
	err = c.decrypt(rep.EncPart, &encApRep)
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

func (c client) decrypt(data datamodel.EncryptedData, dest interface{}) error {
	algorithm := c.encFactory.Create(data.EType)
	return algorithm.Decrypt(data, c.key, dest)
}

func (c client) generateAuthenticator() datamodel.Authenticator {
	// TODO Client implementations SHOULD ensure that the timestamps are not reused
	ctime, usec := datamodel.KerberosTimeNow()
	return datamodel.Authenticator{
		AuthenticatorVNo:  5,
		CRealm:            c.realm,
		CName:             c.cname,
		CKSum:             nil, // TODO calculate checksum
		CUSec:             usec,
		CTime:             ctime,
		SubKey:            nil, // session key from ticket will be used
		SeqNumber:         nil, // TODO support of seq numbers to detect replays
		AuthorizationData: nil, // additional restrictions ontop of specified in a ticket
	}
}

func (c client) encryptAuthenticator(key datamodel.EncryptionKey, auth datamodel.Authenticator) (error, datamodel.EncryptedData) {
	algorithm := c.encFactory.Create(key.KeyType)
	return algorithm.Encrypt(key, auth)
}
