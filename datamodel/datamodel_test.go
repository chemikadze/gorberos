package datamodel

import (
	"testing"
	"time"
)

func assertEquals(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("%v != %v", a, b)
	}
}

func TestPrincipalName(t *testing.T) {
	simplePrincipalName := PrincipalName{0, []KerberosString{"admin"}}
	assertEquals(t, simplePrincipalName.String(), "admin")
	twoElemName := PrincipalName{0, []KerberosString{"admin", "local"}}
	assertEquals(t, twoElemName.String(), "admin/local")
}

func TestKerberosTime(t *testing.T) {
	instance := KerberosTime(time.Unix(0, 0))
	if instance.String() != "19700101000000Z" {
		t.Errorf("%v != %v", instance.String(), "19700101000000Z")
	}
	parsed := KerberosTimeFromString("19700101000000Z")
	if !parsed.ToWire().Equal(instance.ToWire()) {
		t.Errorf("%v != %v", parsed, instance)
	}

	instance2 := KerberosTime(time.Unix(30, 0))
	if instance2.String() != "19700101000030Z" {
		t.Errorf("%v != %v", instance2.String(), "19700101000030Z")
	}
	parsed2 := KerberosTimeFromString("19700101000030Z")
	if !parsed2.ToWire().Equal(instance2.ToWire()) {
		t.Errorf("%v != %v", parsed, instance)
	}
}

func TestKerberosTime_IsEmpty(t *testing.T) {
	a := KerberosTime(time.Unix(0, 0))
	b := KerberosTime(time.Time{})
	var c KerberosTime
	if a.IsEmpty() {
		t.Error("Expected a to be not empty")
	}
	if !b.IsEmpty() {
		t.Error("Expected b to be empty")
	}
	if !c.IsEmpty() {
		t.Error("Expected c to be empty")
	}
}

func TestPrincipalEquality(t *testing.T) {
	x := PrincipalName{NT_UNKNOWN, []KerberosString{"admin", "local"}}
	y := PrincipalName{NT_UNKNOWN, []KerberosString{"admin", "local"}}
	if !x.Equal(y) {
		t.Errorf("%v should equal %v", x, y)
	}
	z := PrincipalName{NT_UNKNOWN, []KerberosString{"admin"}}
	if x.Equal(z) {
		t.Errorf("%v should not equal %v", x, z)
	}
}

func TestKerberosTime_Difference(t *testing.T) {
	a := KerberosTimeFromString("19700101000000Z")
	b := KerberosTimeFromString("19700101000005Z")
	if a.AbsoluteDifference(b) != 5 {
		t.Errorf("diff got %v should be %v", a.AbsoluteDifference(b), 5)
	}
	if a.AbsoluteDifference(b) != b.AbsoluteDifference(a) {
		t.Errorf("inveted args should yield diff result, but %v != %v", a.AbsoluteDifference(b), b.AbsoluteDifference(a))
	}
}

func TestKerberosTime_Plus(t *testing.T) {
	a := KerberosTimeFromString("19700101000000Z")
	b := a.Plus(1)
	assertEquals(t, b.String(), "19700101000001Z")
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

func TestKerberosFlags(t *testing.T) {
	flags := NewKerberosFlags()
	if len(flags.Bytes) != 4 {
		t.Error("")
	}
	if flags.Bytes[0] != 0x00 {
		t.Errorf("%x", flags.Bytes[0])
	}

	flags.Set(7, true)
	if flags.Bytes[0] != 0x01 || !flags.Get(7) {
		t.Errorf("%b", flags.Bytes[0])
	}
	flags.Set(0, true)
	if flags.Bytes[0] != 0x81 || !flags.Get(0) {
		t.Errorf("%b", flags.Bytes[0])
	}
	flags.Set(8, true)
	if flags.Bytes[1] != 0x80 || !flags.Get(8)  {
		t.Errorf("%b", flags.Bytes[1])
	}
	flags.Set(8, false)
	if flags.Bytes[1] != 0x00 || flags.Get(8)  {
		t.Errorf("%b", flags.Bytes[1])
	}
	flags.Set(7, false)
	if flags.Bytes[0] != 0x80 || flags.Get(7)  {
		t.Errorf("%b", flags.Bytes[1])
	}
}

func TestTicketFlags(t *testing.T) {
	flags := NewTicketFlags()
	if len(flags.Bytes) != 4 {
		t.Error("")
	}
	if flags.Bytes[0] != 0x00 {
		t.Errorf("%x", flags.Bytes[0])
	}

	flags.Set(7, true)
	if flags.Bytes[0] != 0x01 || !flags.Get(7) {
		t.Errorf("%b", flags.Bytes[0])
	}
	flags.Set(0, true)
	if flags.Bytes[0] != 0x81 || !flags.Get(0) {
		t.Errorf("%b", flags.Bytes[0])
	}
	flags.Set(8, true)
	if flags.Bytes[1] != 0x80 || !flags.Get(8)  {
		t.Errorf("%b", flags.Bytes[1])
	}
	flags.Set(8, false)
	if flags.Bytes[1] != 0x00 || flags.Get(8)  {
		t.Errorf("%b", flags.Bytes[1])
	}
	flags.Set(7, false)
	if flags.Bytes[0] != 0x80 || flags.Get(7)  {
		t.Errorf("%b", flags.Bytes[1])
	}
}