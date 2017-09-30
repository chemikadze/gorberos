package datamodel

import (
	"testing"
)

func assertEquals(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("%v != %v", a, b)
	}
}

func assertEqualsInt(t *testing.T, a int32, b int32) {
	if a != b {
		t.Errorf("%v != %v", a, b)
	}
}

func TestPrincipalName(t *testing.T) {
	simplePrincipalName := PrincipalName{0, []string{"admin"}}
	assertEquals(t, simplePrincipalName.String(), "admin")
	twoElemName := PrincipalName{0, []string{"admin", "local"}}
	assertEquals(t, twoElemName.String(), "admin/local")
}

func TestKerberosTime(t *testing.T) {
	instance := KerberosTime{0}
	assertEquals(t, instance.String(), "19700101000000Z")
	parsed := KerberosTimeFromString("19700101000000Z")
	assertEquals(t, parsed.Timestamp, instance.Timestamp)
}

func TestAdData(t *testing.T) {
	x := Realm("EXAMPLE.COM")
	var data AuthorizationData = []AuthorizationDataElement{
		AdKdcIssued{
			AdChecksum:         Checksum{42, []byte{0, 1, 2, 3, 4, 5}},
			IssuingRealm:       &x,
			IssuingServiceName: &PrincipalName{NT_SRV_INST, []string{"admin", "local"}},
			Elements: []AuthorizationDataElement{
				AdIfRelevant{},
				AdAndOr{},
				AdMandatoryForKdc{},
			},
		},
	}
	assertEqualsInt(t, data.Get(0).AdType(), AD_KDC_ISSUED)
	assertEquals(t, data.Get(0).(AdKdcIssued).IssuingRealm.String(), "EXAMPLE.COM")
	assertEquals(t, data.Get(0).(AdKdcIssued).IssuingServiceName.String(), "admin/local")
	assertEquals(t, len(data.Get(0).(AdKdcIssued).Elements.Unwrap()), 3)
	assertEqualsInt(t, (data.Get(0).(AdKdcIssued).Elements)[0].AdType(), AD_IF_RELEVANT)
	assertEqualsInt(t, (data.Get(0).(AdKdcIssued).Elements)[1].AdType(), AD_AND_OR)
	assertEqualsInt(t, (data.Get(0).(AdKdcIssued).Elements)[2].AdType(), AD_MANDAROTY_FOR_KDC)
}

func TestPrincipalEquality(t *testing.T) {
	x := PrincipalName{NT_UNKNOWN, []string{"admin", "local"}}
	y := PrincipalName{NT_UNKNOWN, []string{"admin", "local"}}
	if !x.Equal(y) {
		t.Errorf("%v should equal %v", x, y)
	}
	z := PrincipalName{NT_UNKNOWN, []string{"admin"}}
	if x.Equal(z) {
		t.Errorf("%v should not equal %v", x, z)
	}
}

func TestRealmEquality(t *testing.T) {
	x := Realm("EXAMPLE.COM")
	y := Realm("EXAMPLE.COM")
	if x != y {
		t.Errorf("%v should equal %v", x, y)
	}
	z := Realm("TEST.COM")
	if x == z {
		t.Errorf("%v should not equal %v", x, z)
	}
}
