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

func NewMockEncFactory() crypto.Factory {
	return newMockEncFactory()
}

func (f mockEncFactory) Create(etype datamodel.Int32) crypto.Algorithm {
	return f.algo
}

func (mockEncFactory) SupportedETypes() []datamodel.Int32 {
	return []datamodel.Int32{42}
}

func (mockEncFactory) CreateChecksum(cktype datamodel.Int32) crypto.ChecksumAlgorithm {
	return mockCksum{}
}

func (mockEncFactory) ChecksumTypeForEncryption(etype datamodel.Int32) (cktype datamodel.Int32) {
	return etype
}

type mockCksum struct {}

func (mockCksum) GetMic(key datamodel.EncryptionKey, data []byte) crypto.MIC {
	return data
}

func (mockCksum) VerifyMic(key datamodel.EncryptionKey, data []byte, mic crypto.MIC) bool {
	return true
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

func (a mockAlgo) EType() datamodel.Int32 {
	return 42
}

func (a mockAlgo) GenerateKey() datamodel.EncryptionKey {
	return datamodel.EncryptionKey{Keytype: a.EType(), Keyvalue: make([]byte, 0)}
}

func (a *mockAlgo) Encrypt(key datamodel.EncryptionKey, input interface{}) (error, datamodel.EncryptedData) {
	encrypted := datamodel.EncryptedData{}
	encrypted.Etype = a.EType()
	encrypted.Cipher = make([]byte, 1)
	encrypted.Cipher[0] = byte(len(a.state))
	pair := encryptionMapping{encrypted, input}
	a.state = append(a.state, pair)
	return nil, encrypted
}

func (a mockAlgo) Decrypt(input datamodel.EncryptedData, key datamodel.EncryptionKey, result interface{}) error {
	if input.Etype != a.EType() {
		msg := fmt.Sprintf("Unsupported etype %v for algorithm %v\n\nInput: %v", input.Etype, a.EType(), input)
		panic(msg)
		return errors.New(msg)
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
	OnSendAsReq  func(t *MockTransport, req datamodel.AS_REQ) (error, datamodel.AS_REP)
	OnSendApReq  func(t *MockTransport, req datamodel.AP_REQ) (error, datamodel.AP_REP)
	OnSendTgsReq func(t *MockTransport, req datamodel.TGS_REQ) (error, datamodel.TGS_REP)
}

func (t *MockTransport) SendAsReq(req datamodel.AS_REQ) (error, datamodel.AS_REP) {
	return t.OnSendAsReq(t, req)
}

func (t *MockTransport) SendApReq(req datamodel.AP_REQ) (error, datamodel.AP_REP) {
	return t.OnSendApReq(t, req)
}

func (t *MockTransport) SendTgsReq(req datamodel.TGS_REQ) (error, datamodel.TGS_REP) {
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
		if req.Lr_type == datamodel.Int32(lrType) {
			req.Lr_value = time.ToWire()
			princ.LastReq[i] = req
			return nil
		}
	}
	// last req not found
	princ.LastReq = append(princ.LastReq, datamodel.LastReq{{datamodel.Int32(lrType), time.ToWire()}}[0])
	db.principals[princName.String()] = princ
	return nil
}

const (
	ONE_DAY = 24 * 60 * 60
)

// principal database utilities
func newPrincInfo(name string, key datamodel.EncryptionKey) database.PrincipalInfo {
	return database.PrincipalInfo{
		Name:              datamodel.PrincipalNameFromString(name),
		MaxExpirationTime: ONE_DAY,
		MaxRenewTime:      ONE_DAY,
		SecretKeys:        []datamodel.EncryptionKey{key},
	}
}

// mock server-wrapping transport
type noopTransport struct {
	server authsrv.KdcServer
}

func newNoopTransport(server authsrv.KdcServer) gorberos.ClientTransport {
	return &noopTransport{server}
}

func (t *noopTransport) SendAsReq(r datamodel.AS_REQ) (error, datamodel.AS_REP) {
	ok, err, rep := t.server.AuthenticationServerExchange(r)
	if !ok {
		return err, rep
	} else {
		return nil, rep
	}
}

func (t *noopTransport) SendApReq(datamodel.AP_REQ) (error, datamodel.AP_REP) {
	return errors.New("not supported by KDC"), datamodel.AP_REP{}
}

func (t *noopTransport) SendTgsReq(req datamodel.TGS_REQ) (error, datamodel.TGS_REP) {
	ok, err, rep := t.server.TgsExchange(req)
	if !ok {
		return err, rep
	} else {
		return nil, rep
	}
}
