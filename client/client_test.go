package client

import (
	"github.com/chemikadze/gorberos/crypto"
	"github.com/chemikadze/gorberos/datamodel"
	"reflect"
	"strings"
	"testing"
)

type mockEncFactory struct {
	algo *mockAlgo
}

func newMockEncFactory() mockEncFactory {
	algo := newMockAlgo()
	return mockEncFactory{&algo}
}

func (f mockEncFactory) Create(etype int32) crypto.Algorithm {
	return f.algo
}

func (mockEncFactory) SupportedETypes() []int32 {
	return []int32{42}
}

type mockAlgo struct {
	result interface{}
}

func newMockAlgo() mockAlgo {
	return mockAlgo{}
}

func (a mockAlgo) EType() int32 {
	return 0
}

func (a mockAlgo) GenerateKey() []byte {
	return make([]byte, 0)
}

func (a mockAlgo) Encrypt(key datamodel.EncryptionKey, input interface{}) (error, datamodel.EncryptedData) {
	return nil, datamodel.EncryptedData{}
}

func (a mockAlgo) Decrypt(input datamodel.EncryptedData, key datamodel.EncryptionKey, result interface{}) error {
	lvalue := reflect.ValueOf(result)
	rvalue := reflect.ValueOf(a.result)
	for i := 0; i < lvalue.Elem().NumField(); i++ {
		lvalue.Elem().Field(i).Set(rvalue.Field(i))
	}
	return nil
}

type mockTransport struct {
	f         *mockEncFactory
	sendAsReq func(t *mockTransport, req datamodel.AsReq) (error, datamodel.AsRep)
}

func (t *mockTransport) SendAsReq(req datamodel.AsReq) (error, datamodel.AsRep) {
	return t.sendAsReq(t, req)
}

func TestHappyPath(t *testing.T) {
	encFactory := newMockEncFactory()
	client := Client{
		encFactory: encFactory,
		transport: &mockTransport{
			&encFactory,
			func(t *mockTransport, req datamodel.AsReq) (error, datamodel.AsRep) {
				encData := datamodel.EncryptedData{}
				encAsRepPart := datamodel.EncAsRepPart{Nonce: req.ReqBody.NoOnce}
				t.f.algo.result = encAsRepPart
				return nil, datamodel.AsRep{EncPart: encData}
			},
		},
	}
	err := client.Authenticate()
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
}

func TestReplayAttack(t *testing.T) {
	encFactory := newMockEncFactory()
	client := Client{
		encFactory: encFactory,
		transport: &mockTransport{
			&encFactory,
			func(t *mockTransport, req datamodel.AsReq) (error, datamodel.AsRep) {
				encData := datamodel.EncryptedData{}
				encAsRepPart := datamodel.EncAsRepPart{Nonce: 42}
				t.f.algo.result = encAsRepPart
				return nil, datamodel.AsRep{EncPart: encData}
			},
		},
	}
	err := client.Authenticate()
	if err == nil || !strings.Contains(err.Error(), "replay") {
		t.Errorf("Expected replay attack error, got %v", err)
	}
}
