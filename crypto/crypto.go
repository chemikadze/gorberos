package crypto

import (
	"github.com/chemikadze/gorberos/datamodel"
)

type Factory interface {
	EncryptionFactory
	ChecksumFactory
}

type EncryptionFactory interface {
	Create(etype datamodel.Int32) Algorithm
	SupportedETypes() []datamodel.Int32
}

type ChecksumFactory interface {
	CreateChecksum(cktype datamodel.Int32) ChecksumAlgorithm
	ChecksumTypeForEncryption(etype datamodel.Int32) (cktype datamodel.Int32)
}

type Algorithm interface {
	EType() datamodel.Int32
	Decrypt(input datamodel.EncryptedData, key datamodel.EncryptionKey, result interface{}) error
	Encrypt(key datamodel.EncryptionKey, input interface{}) (error, datamodel.EncryptedData)
	GenerateKey() datamodel.EncryptionKey
}

type MIC []byte

type ChecksumAlgorithm interface {
	GetMic(key datamodel.EncryptionKey, data []byte) MIC
	VerifyMic(key datamodel.EncryptionKey, data []byte, mic MIC) bool
}

// see https://tools.ietf.org/html/rfc3961
const (
	CK_CRC32             = 1
	CK_RSA_MD4           = 2
	CK_RSA_MD4_DES       = 3
	CK_DES_MAC           = 4
	CK_DES_MAC_K         = 5
	CK_RSA_MD4_DES_K     = 6
	CK_RSA_MD5           = 7
	CK_RSA_MD5_DES       = 8
	CK_HMAC_SHA1_DES3_KD = 12
)
