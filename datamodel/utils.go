package datamodel

import (
	"fmt"
	"strings"
	"math"
	"time"
)

// KrbError

func NewEmptyError(realm Realm, sname PrincipalName) KrbError {
	ctime, usec := KerberosTimeNowUsec()
	return KrbError{
		CTime: ctime,
		CUSec: usec,
		//ErrorCode: ,
		CRealm: realm,
		SName:  sname,
		//EText:     ,
		//EData:     make([]byte, 0),
	}
}

func NewErrorExt(realm Realm, sname PrincipalName, code int32, msg string) KrbError {
	err := NewEmptyError(realm, sname)
	err.ErrorCode = code
	err.EText = msg
	return err
}

func NewErrorC(realm Realm, sname PrincipalName, code int32) KrbError {
	err := NewEmptyError(realm, sname)
	err.ErrorCode = code
	return err
}

func NewErrorGeneric(realm Realm, sname PrincipalName, msg string) KrbError {
	return NewErrorExt(realm, sname, KRB_ERR_GENERIC, msg)
}

func NoError() KrbError {
	return KrbError{}
}

func (e KrbError) Error() string {
	return fmt.Sprintf("KRB-ERROR %v: %s", e.ErrorCode, e.EText)
}

// ApOptions

func NewApOptions() ApOptions {
	return ApOptions(NewKerberosFlags())
}

// KerberosTime

func KrbTgtForRealm(tgtRealm Realm) PrincipalName {
	return PrincipalName{NameString: []string{KRBTGT, tgtRealm.String()}}
}

func (n PrincipalName) Equal(other PrincipalName) bool {
	if n.NameType != other.NameType || len(n.NameString) != len(other.NameString) {
		return false
	}
	for i, elem := range n.NameString {
		if other.NameString[i] != elem {
			return false
		}
	}
	return true
}

func JoinPrinc(princ PrincipalName, r Realm) string {
	return fmt.Sprintf("%s@%s", princ.String(), r.String())
}

func (p PrincipalName) String() string {
	return strings.Join(p.NameString, "/")
}

func PrincipalNameFromString(str string) PrincipalName {
	return PrincipalName{NT_UNKNOWN, strings.Split(str, "/")}
}

// KerberosTime

func (t KerberosTime) String() string {
	return time.Unix(t.Timestamp, 0).UTC().Format(KERBEROS_TIME_FORMAT)
}

func (t KerberosTime) AbsoluteDifference(t2 KerberosTime) int64 {
	diff := t.Timestamp - t2.Timestamp
	if diff < 0 {
		return -diff
	} else {
		return diff
	}
}

func (t KerberosTime) Difference(t2 KerberosTime) int64 {
	return t.Timestamp - t2.Timestamp
}

func (t KerberosTime) Plus(seconds int64) KerberosTime {
	return KerberosTime{t.Timestamp + seconds}
}

func (t KerberosTime) Minus(seconds int64) KerberosTime {
	return KerberosTime{t.Timestamp - seconds}
}

func KerberosTimeFromString(str string) KerberosTime {
	t, _ := time.ParseInLocation(KERBEROS_TIME_FORMAT, str, time.UTC)
	return KerberosTime{t.Unix()}
}

func KerberosTimeNowUsec() (t KerberosTime, usec int32) {
	now := time.Now()
	return KerberosTime{now.Unix()}, int32(now.Nanosecond() / 1000)
}

func KerberosTimeNow() KerberosTime {
	now, _ := KerberosTimeNowUsec()
	return now
}

func KerberosEpoch() KerberosTime {
	return KerberosTimeFromString("19700101000000Z")
}

func Forever() KerberosTime {
	return KerberosTime{math.MaxInt64}
}

// AuthorizationData

func (a AuthorizationData) Unwrap() []AuthorizationDataElement {
	return []AuthorizationDataElement(a)
}

func (a AuthorizationData) Get(i int) AuthorizationDataElement {
	return []AuthorizationDataElement(a)[i]
}

// KerberosFlags

func NewKerberosFlags() KerberosFlags {
	return NewKerberosFlagsN(32)
}

func NewKerberosFlagsN(n int32) KerberosFlags {
	if n < 32 {
		panic("Min KerberosFlags size is 32 bit")
	}
	return make(KerberosFlags, n)
}

// TicketFlags

func NewTicketFlags() TicketFlags {
	return TicketFlags(NewKerberosFlags())
}

// KdcOptions

func NewKdcOptions() KdcOptions {
	return KdcOptions(NewKerberosFlags())
}

// Realm

func (r Realm) String() string {
	return string(r)
}

