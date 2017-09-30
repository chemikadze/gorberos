package tests

import (
	"errors"
	"fmt"
	"github.com/chemikadze/gorberos"
	"github.com/chemikadze/gorberos/authsrv"
	"github.com/chemikadze/gorberos/crypto"
	"github.com/chemikadze/gorberos/database"
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

func NewMockEncFactory() crypto.EncryptionFactory {
	return newMockEncFactory()
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
type MockTransport struct {
	OnSendAsReq  func(t *MockTransport, req datamodel.AsReq) (error, datamodel.AsRep)
	OnSendApReq  func(t *MockTransport, req datamodel.ApReq) (error, datamodel.ApRep)
	OnSendTgsReq func(t *MockTransport, req datamodel.TgsReq) (error, datamodel.TgsRep)
}

func (t *MockTransport) SendAsReq(req datamodel.AsReq) (error, datamodel.AsRep) {
	return t.OnSendAsReq(t, req)
}

func (t *MockTransport) SendApReq(req datamodel.ApReq) (error, datamodel.ApRep) {
	return t.OnSendApReq(t, req)
}

func (t *MockTransport) SendTgsReq(req datamodel.TgsReq) (error, datamodel.TgsRep) {
	return t.OnSendTgsReq(t, req)
}

// mock principal database
type mockPrincipalDatabase struct {
	principals map[string]database.PrincipalInfo
}

func NewMockDatabase() database.KdcDatabase {
	return &mockPrincipalDatabase{
		principals: make(map[string]database.PrincipalInfo),
	}
}

func (db *mockPrincipalDatabase) InsertPrincipal(princ database.PrincipalInfo) error {
	_, ok := db.principals[princ.Name.String()]
	if ok {
		return errors.New(fmt.Sprintf("Principal %v already exists", princ.Name.String()))
	}
	db.principals[princ.Name.String()] = princ
	return nil
}

func (db *mockPrincipalDatabase) GetPrincipal(princ datamodel.PrincipalName) (database.PrincipalInfo, bool) {
	p, ok := db.principals[princ.String()]
	return p, ok
}

func (db *mockPrincipalDatabase) UpdateLastReq(princName datamodel.PrincipalName, lrType int32, time datamodel.KerberosTime) error {
	princ, ok := db.principals[princName.String()]
	if !ok {
		return errors.New(fmt.Sprintf("Principal %v not found in database", princName.String()))
	}
	for i, req := range princ.LastReq {
		if req.LrType == lrType {
			req.LrValue = time
			princ.LastReq[i] = req
			return nil
		}
	}
	// last req not found
	princ.LastReq = append(princ.LastReq, datamodel.LastReqElement{lrType, time})
	db.principals[princName.String()] = princ
	return nil
}

const (
	ONE_DAY = 24 * 60 * 60
)

// principal database utilities
func newPrincInfo(name string) database.PrincipalInfo {
	return database.PrincipalInfo{
		Name:              datamodel.PrincipalNameFromString(name),
		MaxExpirationTime: ONE_DAY,
		MaxRenewTime:      ONE_DAY,
		SecretKeys:        []datamodel.EncryptionKey{{}},
	}
}

// mock server-wrapping transport
type noopTransport struct {
	server asrv.AuthenticationServer
}

func newNoopTransport(server asrv.AuthenticationServer) gorberos.ClientTransport {
	return &noopTransport{server}
}

func (t *noopTransport) SendAsReq(r datamodel.AsReq) (error, datamodel.AsRep) {
	ok, err, rep := t.server.AuthenticationServerExchange(r)
	if !ok {
		return err, rep
	} else {
		return nil, rep
	}
}

func (t *noopTransport) SendApReq(datamodel.ApReq) (error, datamodel.ApRep) {
	return errors.New("not supported by KDC"), datamodel.ApRep{}
}

func (t *noopTransport) SendTgsReq(datamodel.TgsReq) (error, datamodel.TgsRep) {
	return errors.New("not implemented"), datamodel.TgsRep{}
}
