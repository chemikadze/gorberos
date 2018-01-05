package datamodel

import (
	"fmt"
	"strings"
	"math"
	"time"
	"encoding/asn1"
)

//go:generate asn1go -package datamodel rfc4120.asn1 rfc4120_generated.go

// KrbError

func NewEmptyError(realm Realm, sname PrincipalName) KRB_ERROR {
	ctime, usec := KerberosTimeNowUsec()
	return KRB_ERROR{
		Ctime: ctime.ToWire(),
		Cusec: Microseconds(usec),
		//ErrorCode: ,
		Crealm: realm,
		Sname:  sname,
		//EText:     ,
		//EData:     make([]byte, 0),
	}
}

func NewErrorExt(realm Realm, sname PrincipalName, code int32, msg string) KRB_ERROR {
	err := NewEmptyError(realm, sname)
	err.Error_code = Int32(code)
	err.E_text = KerberosString(msg)
	return err
}

func NewErrorC(realm Realm, sname PrincipalName, code int32) KRB_ERROR {
	err := NewEmptyError(realm, sname)
	err.Error_code = Int32(code)
	return err
}

func NewErrorGeneric(realm Realm, sname PrincipalName, msg string) KRB_ERROR {
	return NewErrorExt(realm, sname, KRB_ERR_GENERIC, msg)
}

func NoError() KRB_ERROR {
	return KRB_ERROR{}
}

func (e KRB_ERROR) Error() string {
	return fmt.Sprintf("KRB-ERROR %v: %s", e.Error_code, e.E_text)
}

// ApOptions

func NewApOptions() APOptions {
	return APOptions(NewKerberosFlags())
}

func (tf *APOptions) Set(index int, value bool) {
	(*KerberosFlags)(tf).Set(index, value)
}

func (tf APOptions) Get(index int) bool {
	return (KerberosFlags)(tf).Get(index)
}

func (tf APOptions) ToWire() asn1.BitString {
	return asn1.BitString(tf)
}

// PrincipalName

func KrbTgtForRealm(tgtRealm Realm) PrincipalName {
	return PrincipalName{
		Name_type: NT_SRV_INST,
		Name_string: []KerberosString{KRBTGT, KerberosString(tgtRealm.String())},
	}
}

func (n PrincipalName) Equal(other PrincipalName) bool {
	if n.Name_type != other.Name_type || len(n.Name_string) != len(other.Name_string) {
		return false
	}
	for i, elem := range n.Name_string {
		if other.Name_string[i] != elem {
			return false
		}
	}
	return true
}

func JoinPrinc(princ PrincipalName, r Realm) string {
	return fmt.Sprintf("%s@%s", princ.String(), r.String())
}

func (p PrincipalName) String() string {
	arr := []string{}
	for _, el := range p.Name_string {
		arr = append(arr, string(el))
	}
	return strings.Join(arr, "/")
}

func (p PrincipalName) IsEmpty() bool {
	return len(p.Name_string) == 0
}

func PrincipalNameFromString(str string) PrincipalName {
	arr := []KerberosString{}
	for _, el := range strings.Split(str, "/") {
		arr = append(arr, KerberosString(el))
	}
	return PrincipalName{NT_UNKNOWN, arr}
}

// KerberosTime

func (t KerberosTime) String() string {
	return t.ToWire().UTC().Format(KERBEROS_TIME_FORMAT)
}

func (t KerberosTime) IsEmpty() bool {
	return t.ToWire().IsZero()
}

func (t KerberosTime) Equal(other KerberosTime) bool {
	return t.ToWire().Equal(other.ToWire())
}

func (t KerberosTime) ToUnix() int64 {
	return t.ToWire().Unix()
}

func (t *KerberosTime) SetTimestamp(val int64) {
	*t = KerberosTime(time.Unix(val, 0))
}

func (t KerberosTime) ToWire() time.Time {
	return time.Time(t)
}

func (t KerberosTime) AbsoluteDifference(t2 KerberosTime) int64 {
	return int64(math.Abs(t.ToWire().Sub(t2.ToWire()).Seconds()))
}

func (t KerberosTime) Difference(t2 KerberosTime) int64 {
	return int64(t.ToWire().Sub(t2.ToWire()))
}

func (t KerberosTime) Plus(seconds int64) KerberosTime {
	return KerberosTime(t.ToWire().Add(time.Duration(seconds) * time.Second))
}

func (t KerberosTime) Minus(seconds int64) KerberosTime {
	return KerberosTime(t.ToWire().Add(-(time.Duration(seconds) * time.Second)))
}

func (t KerberosTime) Min(other KerberosTime) KerberosTime {
	if t.ToWire().Before(other.ToWire()) {
		return t
	} else {
		return other
	}
}

func (t KerberosTime) Max(other KerberosTime) KerberosTime {
	if t.ToWire().After(other.ToWire()) {
		return t
	} else {
		return other
	}
}

func KerberosTimeFromString(str string) KerberosTime {
	t, _ := time.ParseInLocation(KERBEROS_TIME_FORMAT, str, time.UTC)
	return KerberosTime(t)
}

func KerberosTimeFromUnix(secs int64) KerberosTime {
	return KerberosTime(time.Unix(secs, 0).UTC())
}

func KerberosTimeNowUsec() (t KerberosTime, usec int32) {
	now := time.Now()
	return KerberosTime(now), int32(now.Nanosecond() / 1000)
}

func KerberosTimeNow() KerberosTime {
	now, _ := KerberosTimeNowUsec()
	return now
}

func KerberosEpoch() KerberosTime {
	return KerberosTimeFromString("19700101000000Z")
}

// KerberosFlags

func NewKerberosFlags() KerberosFlags {
	return NewKerberosFlagsN(32)
}

func NewKerberosFlagsN(n int32) KerberosFlags {
	if n < 32 {
		panic("Min KerberosFlags size is 32 bit")
	}
	return KerberosFlags(asn1.BitString{[]byte{0x0, 0x0, 0x0, 0x0}, 32})
}

func (tf *KerberosFlags) Set(index int, value bool) {
	x := index / 8
	y := 7 - uint(index%8)
	mask := byte(0x1 << y)
	if value {
		tf.Bytes[x] = tf.Bytes[x] | mask
	} else {
		tf.Bytes[x] = tf.Bytes[x] & (^mask)
	}
}

func (tf KerberosFlags) Get(index int) bool {
	return asn1.BitString(tf).At(index) == 1
}

// TicketFlags

func NewTicketFlags() TicketFlags {
	return TicketFlags(NewKerberosFlags())
}

func (tf *TicketFlags) Set(index int, value bool) {
	(*KerberosFlags)(tf).Set(index, value)
}

func (tf TicketFlags) Get(index int) bool {
	return (KerberosFlags)(tf).Get(index)
}

func (tf TicketFlags) ToWire() asn1.BitString {
	return asn1.BitString(tf)
}

// KdcOptions

func NewKdcOptions() KDCOptions {
	return KDCOptions(NewKerberosFlags())
}

func (tf *KDCOptions) Set(index int, value bool) {
	(*KerberosFlags)(tf).Set(index, value)
}

func (tf KDCOptions) Get(index int) bool {
	return KerberosFlags(tf).Get(index)
}

func (tf KDCOptions) ToWire() asn1.BitString {
	return asn1.BitString(tf)
}

// Realm

func (r Realm) String() string {
	return string(r)
}

func (ek EncryptionKey) IsEmpty() bool {
	return ek.Keytype == 0 && len(ek.Keyvalue) == 0
}

