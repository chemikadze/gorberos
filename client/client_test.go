package client

import (
	"github.com/chemikadze/gorberos/datamodel"
	"strings"
	"testing"
)

func setupHappyPath(encFactory *mockEncFactory, transport *mockTransport) {
	transport.sendAsReq = func(t *mockTransport, req datamodel.AsReq) (error, datamodel.AsRep) {
		encAsRepPart := datamodel.EncAsRepPart{Nonce: req.ReqBody.NoOnce}
		err, encData := encFactory.algo.Encrypt(datamodel.EncryptionKey{}, encAsRepPart)
		return err, datamodel.AsRep{EncPart: encData}
	}
}

func TestApReqHappyPath(t *testing.T) {
	encFactory := newMockEncFactory()
	transport := &mockTransport{}
	setupHappyPath(&encFactory, transport)
	client := client{encFactory: encFactory, transport: transport}
	err := client.Authenticate()
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
}

func TestApReqReplayAttack(t *testing.T) {
	encFactory := newMockEncFactory()
	transport := &mockTransport{}
	transport.sendAsReq = func(t *mockTransport, req datamodel.AsReq) (error, datamodel.AsRep) {
		encAsRepPart := datamodel.EncAsRepPart{Nonce: 42}
		err, encData := encFactory.algo.Encrypt(datamodel.EncryptionKey{}, encAsRepPart)
		return err, datamodel.AsRep{EncPart: encData}
	}
	client := client{encFactory: encFactory, transport: transport}
	err := client.Authenticate()
	if err == nil || !strings.Contains(err.Error(), "replay") {
		t.Errorf("Expected replay attack error, got %v", err)
	}
}

func TestAsReqHappyPath(t *testing.T) {
	encFactory := newMockEncFactory()
	transport := &mockTransport{}
	setupHappyPath(&encFactory, transport)
	transport.sendApReq = func(t *mockTransport, req datamodel.ApReq) (error, datamodel.ApRep) {
		auth := datamodel.Authenticator{}
		encFactory.algo.Decrypt(req.Authenticator, datamodel.EncryptionKey{}, &auth)
		encAsRep := datamodel.EncAPRepPart{CTime: auth.CTime, CUSec: auth.CUSec}
		err, encData := encFactory.algo.Encrypt(datamodel.EncryptionKey{}, encAsRep)
		return err, datamodel.ApRep{EncPart: encData}
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

func TestAsReqWrongCTime(t *testing.T) {
	encFactory := newMockEncFactory()
	transport := &mockTransport{}
	setupHappyPath(&encFactory, transport)
	transport.sendApReq = func(t *mockTransport, req datamodel.ApReq) (error, datamodel.ApRep) {
		auth := datamodel.Authenticator{}
		encFactory.algo.Decrypt(req.Authenticator, datamodel.EncryptionKey{}, &auth)
		encAsRep := datamodel.EncAPRepPart{CTime: datamodel.KerberosTime{12456}, CUSec: auth.CUSec}
		err, encData := encFactory.algo.Encrypt(datamodel.EncryptionKey{}, encAsRep)
		return err, datamodel.ApRep{EncPart: encData}
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
