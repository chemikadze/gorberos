package datamodel

import (
	"fmt"
	"net"
	"strings"
)

type Realm string

func (r Realm) String() string {
	return string(r)
}

// func (Realm) IsValid() bool

type PrincipalName struct {
	NameType   int32
	NameString []string
}

const (
	NT_UNKNOWN        = 0  // Name type not known
	NT_PRINCIPAL      = 1  // Just the name of the principal as in DCE, or for users
	NT_SRV_INST       = 2  // Service and other unique instance (krbtgt)
	NT_SRV_HST        = 3  // Service with host name as instance     (telnet, rcommands)
	NT_SRV_XHST       = 4  // Service with host as remaining components
	NT_UID            = 5  // Unique ID
	NT_X500_PRINCIPAL = 6  // Encoded X.509 Distinguished name [RFC2253]
	NT_SMTP_NAME      = 7  // Name in form of SMTP email name  (e.g., user@example.com)
	NT_ENTERPRISE     = 10 // Enterprise name - may be mapped to principal name

	PVNO             = 5
	TKT_NO           = 5
	AUTHENTICATOR_NO = 5
)

func (p *PrincipalName) String() string {
	return strings.Join(p.NameString, "/")
}

type KerberosTime struct {
	Timestamp uint32
}

func (t KerberosTime) String() string {
	return fmt.Sprintf("%vZ", t.Timestamp)
}

func KerberosTimeFromString(str string) KerberosTime {
	var result KerberosTime
	fmt.Sscanf(str, "%dZ", &result.Timestamp)
	return result
}

/**
  HostAddress     ::= SEQUENCE  {
         addr-type       [0] Int32,
         address         [1] OCTET STRING
  }
*/
type HostAddress struct {
	AddrType int32
	Address  net.IP
}

/**
  -- NOTE: HostAddresses is always used as an OPTIONAL field and
  -- should not be empty.
  HostAddresses   -- NOTE: subtly different from rfc1510,
                 -- but has a value mapping and encodes the same
         ::= SEQUENCE OF HostAddress
*/
type HostAddresses *[]HostAddress

/**
  -- NOTE: AuthorizationData is always used as an OPTIONAL field and
  -- should not be empty.
  AuthorizationData       ::= SEQUENCE OF SEQUENCE {
          ad-type         [0] Int32,
          ad-data         [1] OCTET STRING
  }
*/
type AuthorizationData []AuthorizationDataElement

func (a AuthorizationData) Unwrap() []AuthorizationDataElement {
	return []AuthorizationDataElement(a)
}

func (a AuthorizationData) Get(i int) AuthorizationDataElement {
	return []AuthorizationDataElement(a)[i]
}

type AuthorizationDataElement interface {
	AdType() int32
}

/**
  Contents of ad-data                ad-type

  DER encoding of AD-IF-RELEVANT        1
  DER encoding of AD-KDCIssued          4
  DER encoding of AD-AND-OR             5
  DER encoding of AD-MANDATORY-FOR-KDC  8
*/
const (
	AD_IF_RELEVANT       int32 = 1
	AD_KDC_ISSUED        int32 = 4
	AD_AND_OR            int32 = 5
	AD_MANDAROTY_FOR_KDC int32 = 8
)

/** AD-IF-RELEVANT          ::= AuthorizationData */
type AdIfRelevant struct {
	Data AuthorizationData
}

func (AdIfRelevant) AdType() int32 {
	return AD_IF_RELEVANT
}

/**
   AD-KDCIssued            ::= SEQUENCE {
          ad-checksum     [0] Checksum,
          i-realm         [1] Realm OPTIONAL,
          i-sname         [2] PrincipalName OPTIONAL,
          elements        [3] AuthorizationData
  }
*/
type AdKdcIssued struct {
	AdChecksum         Checksum
	IssuingRealm       *Realm
	IssuingServiceName *PrincipalName
	Elements           AuthorizationData
}

func (AdKdcIssued) AdType() int32 {
	return AD_KDC_ISSUED
}

/**
  AD-AND-OR               ::= SEQUENCE {
       condition-count [0] Int32,
       elements        [1] AuthorizationData
  }
*/
type AdAndOr struct {
	ConditionCount int32
	Elements       AuthorizationData
}

func (AdAndOr) AdType() int32 {
	return AD_AND_OR
}

/**
  AD-MANDATORY-FOR-KDC    ::= AuthorizationData
*/

type AdMandatoryForKdc struct {
	Data AuthorizationDataElement
}

func (AdMandatoryForKdc) AdType() int32 {
	return AD_MANDAROTY_FOR_KDC
}

/**
  PA-DATA         ::= SEQUENCE {
          -- NOTE: first tag is [1], not [0]
          padata-type     [1] Int32,
          padata-value    [2] OCTET STRING -- might be encoded AP-REQ
  }
*/
type PaData struct {
	Type  int32
	Value PaDataPayload
}

type PaDataPayload interface {
	PaType() int32
}

/**
padata-type  Name             Contents of padata-value

      1            pa-tgs-req       DER encoding of AP-REQ
      2            pa-enc-timestamp DER encoding of PA-ENC-TIMESTAMP
      3            pa-pw-salt       salt (not ASN.1 encoded)
      11           pa-etype-info    DER encoding of ETYPE-INFO
      19           pa-etype-info2   DER encoding of ETYPE-INFO2
*/
const (
	PA_TGS_REQ       int32 = 1
	PA_ENC_TIMESTAMP int32 = 2
	PA_PW_SALT       int32 = 3
	PA_ETYPE_INFO    int32 = 11
	PA_ETYPE_INFO2   int32 = 19
)

/**
  PA-ENC-TIMESTAMP        ::= EncryptedData -- PA-ENC-TS-ENC
*/
type PaEncTimestamp EncryptedData

/**
  PA-ENC-TS-ENC           ::= SEQUENCE {
          patimestamp     [0] KerberosTime -- client's time --,
          pausec          [1] Microseconds OPTIONAL
  }
*/
type PaEncTsEnc struct {
	Timestamp KerberosTime
	USec      uint32
}

func (PaEncTsEnc) PaType() int32 {
	return PA_ENC_TIMESTAMP
}

/**
  PA-PW-SALT
*/
type PaPwSalt struct {
	Data []byte
}

func (PaPwSalt) PaType() int32 {
	return PA_PW_SALT
}

/**
  ETYPE-INFO-ENTRY        ::= SEQUENCE {
          etype           [0] Int32,
          salt            [1] OCTET STRING OPTIONAL
  }
*/
type ETypeInfoEntry struct {
	EType int32
	Salt  []byte
}

/**
  ETYPE-INFO              ::= SEQUENCE OF ETYPE-INFO-ENTRY
*/
type ETypeInfo struct {
	Sequence []ETypeInfoEntry
}

func (ETypeInfo) PaType() int32 {
	return PA_ETYPE_INFO
}

/**
ETYPE-INFO2-ENTRY       ::= SEQUENCE {
        etype           [0] Int32,
        salt            [1] KerberosString OPTIONAL,
        s2kparams       [2] OCTET STRING OPTIONAL
}
*/
type ETypeInfo2Entry struct {
	EType     int32
	Salt      string
	S2KParams []byte
}

/**
ETYPE-INFO2              ::= SEQUENCE SIZE (1..MAX) OF ETYPE-INFO2-ENTRY
*/
type ETypeInfo2 struct {
	Sequence []ETypeInfo2Entry
}

func (ETypeInfo2) PaType() int32 {
	return PA_ETYPE_INFO2
}

/**
  KerberosFlags   ::= BIT STRING (SIZE (32..MAX))
                     -- minimum number of bits shall be sent,
                     -- but no fewer than 32
*/
type KerberosFlags []bool

/**
  EncryptedData   ::= SEQUENCE {
          etype   [0] Int32 -- EncryptionType --,
          kvno    [1] UInt32 OPTIONAL,
          cipher  [2] OCTET STRING -- ciphertext
  }
*/
type EncryptedData struct {
	EType  int32
	KVNo   *uint32
	Cipher []byte
}

/**
  EncryptionKey   ::= SEQUENCE {
          keytype         [0] Int32 -- actually encryption type --,
          keyvalue        [1] OCTET STRING
  }
*/
type EncryptionKey struct {
	KeyType  int32
	KeyValue []byte
}

/**
  Checksum        ::= SEQUENCE {
          cksumtype       [0] Int32,
          checksum        [1] OCTET STRING
  }
*/
type Checksum struct {
	CkSumType int32
	Checksum  []byte
}

/**

WIP
WIP
WIP
WIP
WIP
WIP

*/

type Principal struct {
}

/**
  The KRB_KDC_REQ message has no application tag number of its own.
  Instead, it is incorporated into either KRB_AS_REQ or KRB_TGS_REQ,
  each of which has an application tag, depending on whether the
  request is for an initial ticket or an additional ticket.  In either
  case, the message is sent from the client to the KDC to request
  credentials for a service.

  KDC-REQ         ::= SEQUENCE {
    -- NOTE: first tag is [1], not [0]
    pvno            [1] INTEGER (5) ,
    msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
    padata          [3] SEQUENCE OF PA-DATA OPTIONAL
                        -- NOTE: not empty --,
    req-body        [4] KDC-REQ-BODY
    }
*/
type KdcReq struct {
}

type AsReq struct {
	KdcReq
}

type AsRep struct {
	KdcReq
}

type TgsReq struct {
}

func (TgsReq) PaType() int32 {
	return PA_TGS_REQ
}

type TgsRep struct {
}

type ApReq struct {
}

type ApRep struct {
}
