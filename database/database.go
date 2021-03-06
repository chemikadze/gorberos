package database

import "github.com/chemikadze/gorberos/datamodel"

type KdcDatabase interface {
	// get pincipal information
	InsertPrincipal(princ PrincipalInfo) error

	// get pincipal information
	GetPrincipal(princ datamodel.PrincipalName) (PrincipalInfo, bool)

	// update last request information for principal
	UpdateLastReq(princ datamodel.PrincipalName, lrType int32, time datamodel.KerberosTime) error
}

type PrincipalInfo struct {
	Name datamodel.PrincipalName

	SecretKeys []datamodel.EncryptionKey
	LastReq    datamodel.LastReq

	MaxRenewTime      int64
	MaxExpirationTime int64
}
