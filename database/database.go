package database

import "github.com/chemikadze/gorberos/datamodel"

type KdcDatabase interface {
	GetPrincipal(princ datamodel.PrincipalName) (PrincipalInfo, bool)
}

type PrincipalInfo struct {
	SecretKeys   []datamodel.EncryptionKey
	MaxRenewTime int64
}
