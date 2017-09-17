package crypto

import (
	"github.com/chemikadze/gorberos/datamodel"
)

type Factory interface {
	Create(etype int32) Algorithm
	SupportedETypes() []int32
}

type Algorithm interface {
	EType() int32
	Decrypt(input datamodel.EncryptedData, key datamodel.EncryptionKey, result interface{}) error
	Encrypt(key datamodel.EncryptionKey, input interface{}) (error, datamodel.EncryptedData)
	GenerateKey() []byte
}
