package authsrv

import (
	"github.com/chemikadze/gorberos/datamodel"
	"testing"
)

func TestKeyExpiration(t *testing.T) {
	lastReqData := datamodel.LastReq{
		{datamodel.LR_TYPE_ACCOUNT_EXPIRES, datamodel.KerberosTimeFromUnix(500).ToWire()},
		{datamodel.LR_TYPE_PASSWORD_EXPIRES, datamodel.KerberosTimeFromUnix(1000).ToWire()},
		{datamodel.LR_TYPE_ACCOUNT_EXPIRES, datamodel.KerberosTimeFromUnix(2000).ToWire()},
	}
	accountExpiration := lastReqData[0]
	passwordExpiration := lastReqData[1]
	accountExpiration2 := lastReqData[2]
	otherLRElements := datamodel.LastReq{
		{datamodel.LR_TYPE_ANY, datamodel.KerberosTimeFromUnix(10).ToWire()},
		{datamodel.LR_TYPE_INITIAL_REQUEST, datamodel.KerberosTimeFromUnix(11).ToWire()},
		{datamodel.LR_TYPE_RENEWAL, datamodel.KerberosTimeFromUnix(12).ToWire()},
	}
	if !keyExpirationFromLastReq(datamodel.LastReq{}).IsEmpty() {
		t.Error("keyExpiration for empty elems should be nill")
	}
	if !keyExpirationFromLastReq(otherLRElements).IsEmpty() {
		t.Error("keyExpiration from elems with no expiration info should be nill")
	}
	if !keyExpirationFromLastReq(append(otherLRElements, accountExpiration)).ToWire().Equal(accountExpiration.Lr_value) {
		t.Error("keyExpiration should take account expiration")
	}
	if !keyExpirationFromLastReq(append(otherLRElements, passwordExpiration)).ToWire().Equal(passwordExpiration.Lr_value) {
		t.Error("keyExpiration should take password expiration")
	}
	if !keyExpirationFromLastReq(append(otherLRElements, passwordExpiration, accountExpiration)).ToWire().Equal(accountExpiration.Lr_value) {
		t.Error("keyExpiration should take smallest from two expirations")
	}
	if !keyExpirationFromLastReq(append(otherLRElements, accountExpiration, passwordExpiration)).ToWire().Equal(accountExpiration.Lr_value) {
		t.Error("keyExpiration should take smallest from two expirations")
	}
	if !keyExpirationFromLastReq(append(otherLRElements, passwordExpiration, accountExpiration2)).ToWire().Equal(passwordExpiration.Lr_value) {
		t.Error("keyExpiration should take smallest from two expirations")
	}
	if !keyExpirationFromLastReq(append(otherLRElements, accountExpiration2, passwordExpiration)).ToWire().Equal(passwordExpiration.Lr_value) {
		t.Error("keyExpiration should take smallest from two expirations")
	}
}

func TestExpirationTime(t *testing.T) {
	start := datamodel.KerberosTimeFromUnix(1000)
	if getTgtExpirationTime(100, 50, start, datamodel.KerberosTimeFromUnix(1001)).ToUnix() != 1001 {
		t.Error("smallest requestTill should win")
	}
	if getTgtExpirationTime(100, 50, start, datamodel.KerberosTimeFromUnix(2000)).ToUnix() != 1050 {
		t.Error("smallest policy should win")
	}
	if getTgtExpirationTime(20, 50, start, datamodel.KerberosTimeFromUnix(2000)).ToUnix() != 1020 {
		t.Error("smallest policy should win")
	}
}
