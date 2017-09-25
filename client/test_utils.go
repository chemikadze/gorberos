package client

import (
	"errors"
	"github.com/chemikadze/gorberos/crypto"
	"github.com/chemikadze/gorberos/datamodel"
	"log"
	"reflect"
)

// mock encryption entry point
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

// only encryption algorithm exposed by factory
// creates mock EncryptedData objects and remembers result for decryption
type mockAlgo struct {
	state []encryptionMapping
}

type encryptionMapping struct {
	encrypted datamodel.EncryptedData
	decrypted interface{}
}

func newMockAlgo() mockAlgo {
	return mockAlgo{}
}

func (a mockAlgo) EType() int32 {
	return 42
}

func (a mockAlgo) GenerateKey() []byte {
	return make([]byte, 0)
}

func (a *mockAlgo) Encrypt(key datamodel.EncryptionKey, input interface{}) (error, datamodel.EncryptedData) {
	encrypted := datamodel.EncryptedData{}
	encrypted.EType = a.EType()
	encrypted.Cipher = make([]byte, 1)
	encrypted.Cipher[0] = byte(len(a.state))
	pair := encryptionMapping{encrypted, input}
	a.state = append(a.state, pair)
	return nil, encrypted
}

func (a mockAlgo) Decrypt(input datamodel.EncryptedData, key datamodel.EncryptionKey, result interface{}) error {
	if input.EType != a.EType() {
		return errors.New("Unsupported etype")
	}
	if len(input.Cipher) != 1 {
		return errors.New("Mock encrypted data should be one byte long")
	}
	if input.Cipher[0] >= byte(len(a.state)) {
		return errors.New("Not found mock reply for encrypted mock message")
	}
	data := a.state[input.Cipher[0]].decrypted
	lvalue := reflect.ValueOf(result)
	rvalue := reflect.ValueOf(data)
	i := 0
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Failed on fields %v %v", lvalue, rvalue)
			log.Printf("Failed on fields %v %v", lvalue.Elem().Field(i), rvalue.Elem().Field(i))
		}
	}()
	for i = 0; i < lvalue.Elem().NumField(); i++ {
		lvalue.Elem().Field(i).Set(rvalue.Field(i))
	}
	return nil
}

// mock transport
type mockTransport struct {
	sendAsReq  func(t *mockTransport, req datamodel.AsReq) (error, datamodel.AsRep)
	sendApReq  func(t *mockTransport, req datamodel.ApReq) (error, datamodel.ApRep)
	sendTgsReq func(t *mockTransport, req datamodel.TgsReq) (error, datamodel.TgsRep)
}

func (t *mockTransport) SendAsReq(req datamodel.AsReq) (error, datamodel.AsRep) {
	return t.sendAsReq(t, req)
}

func (t *mockTransport) SendApReq(req datamodel.ApReq) (error, datamodel.ApRep) {
	return t.sendApReq(t, req)
}

func (t *mockTransport) SendTgsReq(req datamodel.TgsReq) (error, datamodel.TgsRep) {
	return t.sendTgsReq(t, req)
}
