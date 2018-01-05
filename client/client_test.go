package client

import (
	"github.com/chemikadze/gorberos/crypto"
	"github.com/chemikadze/gorberos/datamodel"
	"github.com/chemikadze/gorberos/tests"
	"strings"
	"testing"
)

func setupAsHappyPath(encFactory crypto.EncryptionFactory, transport *tests.MockTransport) {
	transport.OnSendAsReq = func(t *tests.MockTransport, req datamodel.AS_REQ) (error, datamodel.AS_REP) {
		encAsRepPart := datamodel.EncASRepPart{Nonce: req.Req_body.Nonce, Sname: req.Req_body.Sname}
		algo := encFactory.Create(encFactory.SupportedETypes()[0])
		err, encData := algo.Encrypt(datamodel.EncryptionKey{}, encAsRepPart)
		return err, datamodel.AS_REP{Enc_part: encData}
	}
}

func TestAsReqHappyPath(t *testing.T) {
	encFactory := tests.NewMockEncFactory()
	transport := &tests.MockTransport{}
	setupAsHappyPath(encFactory, transport)
	client := client{encFactory: encFactory, transport: transport}
	err := client.Authenticate()
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
}

func TestAsReqReplayAttack(t *testing.T) {
	encFactory := tests.NewMockEncFactory()
	transport := &tests.MockTransport{}
	transport.OnSendAsReq = func(t *tests.MockTransport, req datamodel.AS_REQ) (error, datamodel.AS_REP) {
		encAsRepPart := datamodel.EncASRepPart{Nonce: 42}
		algo := encFactory.Create(encFactory.SupportedETypes()[0])
		err, encData := algo.Encrypt(datamodel.EncryptionKey{}, encAsRepPart)
		return err, datamodel.AS_REP{Enc_part: encData}
	}
	client := client{encFactory: encFactory, transport: transport}
	err := client.Authenticate()
	if err == nil || !strings.Contains(err.Error(), "replay") {
		t.Errorf("Expected replay attack error, got %v", err)
	}
}

func TestApReqHappyPath(t *testing.T) {
	encFactory := tests.NewMockEncFactory()
	transport := &tests.MockTransport{}
	setupAsHappyPath(encFactory, transport)
	transport.OnSendApReq = func(t *tests.MockTransport, req datamodel.AP_REQ) (error, datamodel.AP_REP) {
		auth := datamodel.Authenticator{}
		algo := encFactory.Create(encFactory.SupportedETypes()[0])
		algo.Decrypt(req.Authenticator, datamodel.EncryptionKey{}, &auth)
		encAsRep := datamodel.EncAPRepPart{Ctime: auth.Ctime, Cusec: auth.Cusec}
		err, encData := algo.Encrypt(datamodel.EncryptionKey{}, encAsRep)
		return err, datamodel.AP_REP{Enc_part: encData}
	}
	client := client{encFactory: encFactory, transport: transport, apUseSessionKey: true}
	err := client.Authenticate()
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	err = client.AuthenticateApplication()
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
}

func TestApReqWrongCTime(t *testing.T) {
	encFactory := tests.NewMockEncFactory()
	transport := &tests.MockTransport{}
	setupAsHappyPath(encFactory, transport)
	transport.OnSendApReq = func(t *tests.MockTransport, req datamodel.AP_REQ) (error, datamodel.AP_REP) {
		auth := datamodel.Authenticator{}
		algo := encFactory.Create(encFactory.SupportedETypes()[0])
		algo.Decrypt(req.Authenticator, datamodel.EncryptionKey{}, &auth)
		encAsRep := datamodel.EncAPRepPart{Ctime: datamodel.KerberosTimeFromUnix(12456).ToWire(), Cusec: auth.Cusec}
		err, encData := algo.Encrypt(datamodel.EncryptionKey{}, encAsRep)
		return err, datamodel.AP_REP{Enc_part: encData}
	}
	client := client{encFactory: encFactory, transport: transport, apUseSessionKey: true}
	err := client.Authenticate()
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	err = client.AuthenticateApplication()
	if err == nil || !strings.Contains(err.Error(), "Response CTime or CUSec did not match those of authenticator") {
		t.Errorf("Expected authenticator validation error, got %v", err)
	}
}
