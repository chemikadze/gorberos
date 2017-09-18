package asrv

import (
	"github.com/chemikadze/gorberos/datamodel"
	"testing"
)

func TestKeyExpiration(t *testing.T) {
	accountExpiration := datamodel.LastReqElement{datamodel.LR_TYPE_ACCOUNT_EXPIRES, datamodel.KerberosTime{500}}
	passwordExpiration := datamodel.LastReqElement{datamodel.LR_TYPE_PASSWORD_EXPIRES, datamodel.KerberosTime{1000}}
	accountExpiration2 := datamodel.LastReqElement{datamodel.LR_TYPE_ACCOUNT_EXPIRES, datamodel.KerberosTime{2000}}
	otherLRElements := datamodel.LastReq{
		datamodel.LastReqElement{LrType: datamodel.LR_TYPE_ANY, LrValue: datamodel.KerberosTime{10}},
		datamodel.LastReqElement{LrType: datamodel.LR_TYPE_INITIAL_REQUEST, LrValue: datamodel.KerberosTime{11}},
		datamodel.LastReqElement{LrType: datamodel.LR_TYPE_RENEWAL, LrValue: datamodel.KerberosTime{12}},
	}
	if keyExpirationFromLastReq(datamodel.LastReq{}) != nil {
		t.Error("keyExpiration for empty elems should be nill")
	}
	if keyExpirationFromLastReq(otherLRElements) != nil {
		t.Error("keyExpiration from elems with no expiration info should be nill")
	}
	if *keyExpirationFromLastReq(append(otherLRElements, accountExpiration)) != accountExpiration.LrValue {
		t.Error("keyExpiration should take account expiration")
	}
	if *keyExpirationFromLastReq(append(otherLRElements, passwordExpiration)) != passwordExpiration.LrValue {
		t.Error("keyExpiration should take password expiration")
	}
	if *keyExpirationFromLastReq(append(otherLRElements, passwordExpiration, accountExpiration)) != accountExpiration.LrValue {
		t.Error("keyExpiration should take smallest from two expirations")
	}
	if *keyExpirationFromLastReq(append(otherLRElements, accountExpiration, passwordExpiration)) != accountExpiration.LrValue {
		t.Error("keyExpiration should take smallest from two expirations")
	}
	if *keyExpirationFromLastReq(append(otherLRElements, passwordExpiration, accountExpiration2)) != passwordExpiration.LrValue {
		t.Error("keyExpiration should take smallest from two expirations")
	}
	if *keyExpirationFromLastReq(append(otherLRElements, accountExpiration2, passwordExpiration)) != passwordExpiration.LrValue {
		t.Error("keyExpiration should take smallest from two expirations")
	}
}
