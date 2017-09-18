package database

import "github.com/chemikadze/gorberos/datamodel"

type KdcDatabase interface {
	// get pincipal information
	GetPrincipal(princ datamodel.PrincipalName) (PrincipalInfo, bool)

	// update last request information for principal
	UpdateLastReq(princ datamodel.PrincipalName, lrType int32, time datamodel.KerberosTime) error
}

type PrincipalInfo struct {
	SecretKeys   []datamodel.EncryptionKey
	MaxRenewTime int64
	LastReq      datamodel.LastReq
}
