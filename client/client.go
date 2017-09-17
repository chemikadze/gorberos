package client

import (
	"crypto/rand"
	"errors"
	"github.com/chemikadze/gorberos"
	"github.com/chemikadze/gorberos/crypto"
	"github.com/chemikadze/gorberos/datamodel"
	"math"
	"math/big"
	"time"
)

type Client struct {
	transport     gorberos.ClientTransport
	tgt           datamodel.Ticket
	cname         datamodel.PrincipalName
	sname         datamodel.PrincipalName
	realm         datamodel.Realm
	encFactory    crypto.Factory
	keyExpiration *uint32
	key datamodel.EncryptionKey
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
	if c.keyExpiration != nil {
		till = time.Now().Unix() + int64(*c.keyExpiration)
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
	// The encrypted part of the KRB_AS_REP message also contains the nonce
	// that MUST be matched with the nonce from the KRB_AS_REQ message.
	err, encRep := c.decryptData(rep.EncPart)
	if encRep.NoNCE != nonce {
		return errors.New("Potential replay attack: nonce of KRB_AS_REP did not match nonce of KRB_AS_REQ")
	}
	c.tgt = rep.Ticket
	return nil
}

func (c Client) decryptData(data datamodel.EncryptedData) (error, datamodel.EncAsRepPart) {
	algorithm := c.encFactory.Create(data.EType)
	result := &datamodel.EncAsRepPart{}
	err := algorithm.Decrypt(data, c.key, result)
	return err, *result
}
