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

type Client struct {
	transport    gorberos.ClientTransport
	tgt          datamodel.Ticket
	cname        datamodel.PrincipalName
	sname        datamodel.PrincipalName
	realm        datamodel.Realm
	encFactory   crypto.Factory
	keyLifetime  *uint32
	key          datamodel.EncryptionKey
	sessionKey   datamodel.EncryptionKey
	keyStartTime *datamodel.KerberosTime
	keyEndTime   datamodel.KerberosTime
}

func New(transport gorberos.ClientTransport) gorberos.Client {
	return Client{
		transport: transport,
	}
}

func (c Client) Authenticate() error {
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
	err, encRep := c.decryptData(rep.EncPart)
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

func (c Client) decryptData(data datamodel.EncryptedData) (error, datamodel.EncAsRepPart) {
	algorithm := c.encFactory.Create(data.EType)
	result := &datamodel.EncAsRepPart{}
	err := algorithm.Decrypt(data, c.key, result)
	return err, *result
}
