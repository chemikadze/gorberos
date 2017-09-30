package datamodel

import (
	"fmt"
	"math"
	"net"
	"strings"
	"time"
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

	MSG_TYPE_KRB_AP_REQ = 14
)

func (p *PrincipalName) String() string {
	return strings.Join(p.NameString, "/")
}

func PrincipalNameFromString(str string) PrincipalName {
	return PrincipalName{NT_UNKNOWN, strings.Split(str, "/")}
}

type KerberosTime struct {
	Timestamp int64
}

const (
	KERBEROS_TIME_FORMAT = "20060102150405Z"
)

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

func KerberosTimeFromString(str string) KerberosTime {
	t, _ := time.ParseInLocation(KERBEROS_TIME_FORMAT, str, time.UTC)
	return KerberosTime{t.Unix()}
}

func KerberosTimeNow() (t KerberosTime, usec int32) {
	now := time.Now()
	return KerberosTime{now.Unix()}, int32(now.Nanosecond() / 1000)
}

func KerberosEpoch() KerberosTime {
	return KerberosTimeFromString("19700101000000Z")
}

func Forever() KerberosTime {
	return KerberosTime{math.MaxInt64}
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

func NewKerberosFlags() KerberosFlags {
	return NewKerberosFlagsN(32)
}

func NewKerberosFlagsN(n int32) KerberosFlags {
	if n < 32 {
		panic("Min KerberosFlags size is 32 bit")
	}
	return make(KerberosFlags, n)
}

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
  Ticket          ::= [APPLICATION 1] SEQUENCE {
          tkt-vno         [0] INTEGER (5),
          realm           [1] Realm,
          sname           [2] PrincipalName,
          enc-part        [3] EncryptedData -- EncTicketPart
  }
*/
type Ticket struct {
	VNo     int32
	Realm   Realm
	SName   PrincipalName
	EncPart EncryptedData
}

/**
  EncTicketPart   ::= [APPLICATION 3] SEQUENCE {
          flags                   [0] TicketFlags,
          key                     [1] EncryptionKey,
          crealm                  [2] Realm,
          cname                   [3] PrincipalName,
          transited               [4] TransitedEncoding,
          authtime                [5] KerberosTime,
          starttime               [6] KerberosTime OPTIONAL,
          endtime                 [7] KerberosTime,
          renew-till              [8] KerberosTime OPTIONAL,
          caddr                   [9] HostAddresses OPTIONAL,
          authorization-data      [10] AuthorizationData OPTIONAL
  }
*/
type EncTicketPart struct {
	Flags             TicketFlags
	Key               EncryptionKey
	CRealm            Realm
	CName             PrincipalName
	Transited         TransitedEncoding
	AuthTime          KerberosTime
	StartTime         *KerberosTime
	EndTime           KerberosTime
	RenewTill         *KerberosTime
	CAddr             HostAddresses
	AuthorizationData AuthorizationData
}

/**
  -- encoded Transited field
  TransitedEncoding       ::= SEQUENCE {
          tr-type         [0] Int32 -- must be registered --,
          contents        [1] OCTET STRING
  }
*/
type TransitedEncoding struct {
	TrType   int32
	Contents []byte
}

/**
  TicketFlags     ::= KerberosFlags
          -- reserved(0),
          -- forwardable(1),
          -- forwarded(2),
          -- proxiable(3),
          -- proxy(4),
          -- may-postdate(5),
          -- postdated(6),
          -- invalid(7),
          -- renewable(8),
          -- initial(9),
          -- pre-authent(10),
          -- hw-authent(11),
  -- the following are new since 1510
          -- transited-policy-checked(12),
          -- ok-as-delegate(13)
*/
type TicketFlags KerberosFlags

func NewTicketFlags() TicketFlags {
	return TicketFlags(NewKerberosFlags())
}

const (
	//it is OK to issue a new TGT with a different network address based on the presented ticket
	TKT_FLAG_FORWARDABLE = 1

	// same as FORWARDABLE except it tells the ticket-granting server that
	// only non-TGTs may be issued with different network addresses
	TKT_FLAG_PROXIABLE = 3

	// tells TGS that postdated ticket MAY be issued based on this TGT
	TKT_FLAG_MAY_POSTDATE = 5

	// tells if it is postdated
	TKT_FLAG_POSTDATED = 6

	TKT_FLAG_INVALID = 7

	// used by TGS, to obtain replacement ticket that expires at later date
	TKT_FLAG_RENEWABLE = 8

	// got via AS rather than TGS exchange
	TKT_FLAG_INITIAL = 9
)

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
	PvNo    int32
	MsgType int64
	PaData  []PaData // preauth data
	ReqBody KdcReqBody
}

/**
  KDC-REQ-BODY    ::= SEQUENCE {
      kdc-options             [0] KDCOptions,
      cname                   [1] PrincipalName OPTIONAL
                                  -- Used only in AS-REQ --,
      realm                   [2] Realm
                                  -- Server's realm
                                  -- Also client's in AS-REQ --,
      sname                   [3] PrincipalName OPTIONAL,
      from                    [4] KerberosTime OPTIONAL,
      till                    [5] KerberosTime,
      rtime                   [6] KerberosTime OPTIONAL,
      nonce                   [7] UInt32,
      etype                   [8] SEQUENCE OF Int32 -- EncryptionType
                                  -- in preference order --,
      addresses               [9] HostAddresses OPTIONAL,
      enc-authorization-data  [10] EncryptedData OPTIONAL
                                  -- AuthorizationData --,
      additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
                                     -- NOTE: not empty
  }
*/
type KdcReqBody struct {
	KdcOptions KdcOptions

	// client's principal
	CName PrincipalName

	// in the AS exchange, this is also the realm part of the client's principal identifier
	Realm Realm

	// server identity, may only be absent when the ENC-TKT-IN-SKEY option is specified
	SName *PrincipalName

	// included in the KRB_AS_REQ and KRB_TGS_REQ ticket requests when the requested ticket is to be postdated
	// specifies the desired starttime for the requested ticket
	From *KerberosTime

	// expiration date requested by the client
	// if the requested endtime is "19700101000000Z", the requested ticket
	// is to have the maximum endtime permitted according to KDC policy
	Till KerberosTime

	// requested renew-till time
	RTime *KerberosTime
	Nonce uint32

	// desired encryption algorithm
	EType []int32

	// required for initial request for tickets
	// usually copied by the KDC into the caddr field of the resulting ticket
	Addresses HostAddresses

	// can only be present in the TGS_REQ form
	EncAuthorizationData *EncryptedData

	// If the ENC-TKT-IN-SKEY option has been specified, then the session key from the additional ticket will be
	// used in place of the server's key to encrypt the new ticket.  When
	// the ENC-TKT-IN-SKEY option is used for user-to-user
	// authentication, this additional ticket MAY be a TGT issued by the
	// local realm or an inter-realm TGT issued for the current KDC's
	// realm by a remote KDC
	AdditionalTickets []Ticket
}

/**
KDCOptions      ::= KerberosFlags
        -- reserved(0),
        -- forwardable(1),
        -- forwarded(2),
        -- proxiable(3),
        -- proxy(4),
        -- allow-postdate(5),
        -- postdated(6),
        -- unused7(7),
        -- renewable(8),
        -- unused9(9),
        -- unused10(10),
        -- opt-hardware-auth(11),
        -- unused12(12),
        -- unused13(13),
-- 15 is reserved for canonicalize
        -- unused15(15),
-- 26 was unused in 1510
        -- disable-transited-check(26),
--
        -- renewable-ok(27),
        -- enc-tkt-in-skey(28),
        -- renew(30),
        -- validate(31)
*/
type KdcOptions KerberosFlags

func NewKdcOptions() KdcOptions {
	return KdcOptions(NewKerberosFlags())
}

const (
	KDC_FLAG_FORWARDABLE    = 1
	KDC_FLAG_FORWARDED      = 2
	KDC_FLAG_PROXIABLE      = 3
	KDC_FLAG_PROXY          = 4
	KDC_FLAG_ALLOW_POSTDATE = 5
	KDC_FLAG_POSTDATED      = 6
	KDC_FLAG_RENEWABLE      = 8
	KDC_FLAG_RENEWABLE_OK   = 27
	KDC_ENC_TICKET_IN_SKEY  = 28
	KDC_FLAG_RENEW          = 30 // TODO implement in client
)

/**
  AS-REQ          ::= [APPLICATION 10] KDC-REQ
*/
type AsReq KdcReq

/**
  AS-REP          ::= [APPLICATION 11] KDC-REP
*/
type AsRep KdcRep

/**
  TGS-REQ         ::= [APPLICATION 12] KDC-REQ
*/
type TgsReq KdcReq

func (TgsReq) PaType() int32 {
	return PA_TGS_REQ
}

/**
  TGS-REP         ::= [APPLICATION 13] KDC-REP
*/
type TgsRep KdcRep

/**
  KDC-REP         ::= SEQUENCE {
          pvno            [0] INTEGER (5),
          msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
          padata          [2] SEQUENCE OF PA-DATA OPTIONAL
                                  -- NOTE: not empty --,
          crealm          [3] Realm,
          cname           [4] PrincipalName,
          ticket          [5] Ticket,
          enc-part        [6] EncryptedData
                                  -- EncASRepPart or EncTGSRepPart,
                                  -- as appropriate
  }
*/
type KdcRep struct {
	PvNo    int32
	MsgType int32
	PaData  []PaData
	CRealm  Realm
	CName   PrincipalName
	Ticket  Ticket
	EncPart EncryptedData
}

/**
  EncASRepPart    ::= [APPLICATION 25] EncKDCRepPart
*/
type EncAsRepPart EncKDCRepPart

/**
  EncTGSRepPart   ::= [APPLICATION 26] EncKDCRepPart
*/
type EncTGSRepPart EncKDCRepPart

/**
   EncKDCRepPart   ::= SEQUENCE {
          key             [0] EncryptionKey,
          last-req        [1] LastReq,
          nonce           [2] UInt32,
          key-expiration  [3] KerberosTime OPTIONAL,
          flags           [4] TicketFlags,
          authtime        [5] KerberosTime,
          starttime       [6] KerberosTime OPTIONAL,
          endtime         [7] KerberosTime,
          renew-till      [8] KerberosTime OPTIONAL,
          srealm          [9] Realm,
          sname           [10] PrincipalName,
          caddr           [11] HostAddresses OPTIONAL
  }
*/
type EncKDCRepPart struct {
	Key           EncryptionKey
	LastReq       LastReq
	Nonce         uint32
	KeyExpiration *KerberosTime // *secret* key expiration
	Flags         TicketFlags
	AuthTime      KerberosTime
	StartTime     *KerberosTime
	EndTime       KerberosTime
	RenewTill     *KerberosTime
	SRealm        Realm
	SName         PrincipalName
	CAddr         HostAddresses
}

/**
  LastReq         ::=     SEQUENCE OF SEQUENCE {
          lr-type         [0] Int32,
          lr-value        [1] KerberosTime
  }
*/
type LastReq []LastReqElement

type LastReqElement struct {
	LrType  int32
	LrValue KerberosTime
}

/**
If the lr-type field is zero (0), then no information is conveyed
     by the lr-value subfield.  If the absolute value of the lr-type
     field is one (1), then the lr-value subfield is the time of last
     initial request for a TGT.  If it is two (2), then the lr-value
     subfield is the time of last initial request.  If it is three (3),
     then the lr-value subfield is the time of issue for the newest TGT
     used.  If it is four (4), then the lr-value subfield is the time
     of the last renewal.  If it is five (5), then the lr-value
     subfield is the time of last request (of any type).  If it is (6),
     then the lr-value subfield is the time when the password will
     expire.  If it is (7), then the lr-value subfield is the time when
     the account will expire.
*/
const (
	LR_TYPE_NO                  = 0
	LR_TYPE_TGT_INITIAL_REQUEST = 1
	LR_TYPE_INITIAL_REQUEST     = 2
	LR_TYPE_TGT                 = 3
	LR_TYPE_RENEWAL             = 4
	LR_TYPE_ANY                 = 5
	LR_TYPE_PASSWORD_EXPIRES    = 6
	LR_TYPE_ACCOUNT_EXPIRES     = 7
)

/**
  AP-REQ          ::= [APPLICATION 14] SEQUENCE {
          pvno            [0] INTEGER (5),
          msg-type        [1] INTEGER (14),
          ap-options      [2] APOptions,
          ticket          [3] Ticket,
          authenticator   [4] EncryptedData -- Authenticator
  }
*/
type ApReq struct {
	PvNo      int32
	MsgType   int32
	ApOptions ApOptions
	Ticket    Ticket

	// certifies to a server that the sender has recent knowledge of
	// the encryption key in the accompanying ticket
	Authenticator EncryptedData
}

/**
  APOptions       ::= KerberosFlags
          -- reserved(0),
          -- use-session-key(1),
          -- mutual-required(2)
*/
type ApOptions KerberosFlags

func NewApOptions() ApOptions {
	return ApOptions(NewKerberosFlags())
}

const (
	AP_FLAG_RESERVED        = 0
	AP_FLAG_USE_SESSION_KEY = 1
	AP_FLAG_MUTUAL_REQUIRED = 2
)

/**
-- Unencrypted authenticator
   Authenticator   ::= [APPLICATION 2] SEQUENCE  {
           authenticator-vno       [0] INTEGER (5),
           crealm                  [1] Realm,
           cname                   [2] PrincipalName,
           cksum                   [3] Checksum OPTIONAL,
           cusec                   [4] Microseconds,
           ctime                   [5] KerberosTime,
           subkey                  [6] EncryptionKey OPTIONAL,
           seq-number              [7] UInt32 OPTIONAL,
           authorization-data      [8] AuthorizationData OPTIONAL
   }
*/
type Authenticator struct {
	AuthenticatorVNo  int32
	CRealm            Realm
	CName             PrincipalName
	CKSum             *Checksum
	CUSec             int32
	CTime             KerberosTime
	SubKey            *EncryptionKey
	SeqNumber         *uint32
	AuthorizationData *AuthorizationData
}

/**
  AP-REP          ::= [APPLICATION 15] SEQUENCE {
          pvno            [0] INTEGER (5),
          msg-type        [1] INTEGER (15),
          enc-part        [2] EncryptedData -- EncAPRepPart
  }
*/
type ApRep struct {
	PVNo    int32
	MsgType int32
	EncPart EncryptedData
}

/**
  EncAPRepPart    ::= [APPLICATION 27] SEQUENCE {
          ctime           [0] KerberosTime,
          cusec           [1] Microseconds,
          subkey          [2] EncryptionKey OPTIONAL,
          seq-number      [3] UInt32 OPTIONAL
  }
*/
type EncAPRepPart struct {
	CTime     KerberosTime
	CUSec     int32
	SubKey    *EncryptionKey
	SeqNumber *uint32
}

/**
  KRB-SAFE        ::= [APPLICATION 20] SEQUENCE {
          pvno            [0] INTEGER (5),
          msg-type        [1] INTEGER (20),
          safe-body       [2] KRB-SAFE-BODY,
          cksum           [3] Checksum
  }
*/
type KrbSafe struct {
	PvNo     int32
	MsgType  int32
	SafeBody KrbSafeBody
	CKSum    Checksum
}

/**
  KRB-SAFE-BODY   ::= SEQUENCE {
          user-data       [0] OCTET STRING,
          timestamp       [1] KerberosTime OPTIONAL,
          usec            [2] Microseconds OPTIONAL,
          seq-number      [3] UInt32 OPTIONAL,
          s-address       [4] HostAddress,
          r-address       [5] HostAddress OPTIONAL
  }
*/
type KrbSafeBody struct {
	UserData  []byte
	Timestamp *KerberosTime
	USec      *int32
	SeqNumber *uint32
	SAddress  HostAddress
	RAddress  *HostAddress
}

/**
  KRB-PRIV        ::= [APPLICATION 21] SEQUENCE {
          pvno            [0] INTEGER (5),
          msg-type        [1] INTEGER (21),
                          -- NOTE: there is no [2] tag
          enc-part        [3] EncryptedData -- EncKrbPrivPart
  }
*/
type KrbPriv struct {
	PvNo    int32
	MsgType int32
	EncPart EncryptedData
}

/**
  EncKrbPrivPart  ::= [APPLICATION 28] SEQUENCE {
          user-data       [0] OCTET STRING,
          timestamp       [1] KerberosTime OPTIONAL,
          usec            [2] Microseconds OPTIONAL,
          seq-number      [3] UInt32 OPTIONAL,
          s-address       [4] HostAddress -- sender's addr --,
          r-address       [5] HostAddress OPTIONAL -- recip's addr
  }
*/
type EncKrbPrivPart struct {
	UserData  []byte
	Timestamp *KerberosTime
	USec      *int32
	SeqNumber *uint32
	SAddress  HostAddress
	RAddress  *HostAddress
}

/**
  KRB-CRED        ::= [APPLICATION 22] SEQUENCE {
          pvno            [0] INTEGER (5),
          msg-type        [1] INTEGER (22),
          tickets         [2] SEQUENCE OF Ticket,
          enc-part        [3] EncryptedData -- EncKrbCredPart
  }
*/
type KrbCred struct {
	PvNo    int32
	MsgType int32
	Tickets []Ticket
	EncPart EncryptedData
}

/**
  EncKrbCredPart  ::= [APPLICATION 29] SEQUENCE {
          ticket-info     [0] SEQUENCE OF KrbCredInfo,
          nonce           [1] UInt32 OPTIONAL,
          timestamp       [2] KerberosTime OPTIONAL,
          usec            [3] Microseconds OPTIONAL,
          s-address       [4] HostAddress OPTIONAL,
          r-address       [5] HostAddress OPTIONAL
  }
*/
type EncKrbCredPart struct {
	TicketInfo  []KrbCredInfo
	NoNCE       *uint32
	Timestamp   *KerberosTime
	USec        *int32
	HostAddress HostAddress
	RAddress    HostAddress
}

/**
  KrbCredInfo     ::= SEQUENCE {
          key             [0] EncryptionKey,
          prealm          [1] Realm OPTIONAL,
          pname           [2] PrincipalName OPTIONAL,
          flags           [3] TicketFlags OPTIONAL,
          authtime        [4] KerberosTime OPTIONAL,
          starttime       [5] KerberosTime OPTIONAL,
          endtime         [6] KerberosTime OPTIONAL,
          renew-till      [7] KerberosTime OPTIONAL,
          srealm          [8] Realm OPTIONAL,
          sname           [9] PrincipalName OPTIONAL,
          caddr           [10] HostAddresses OPTIONAL
  }
*/
type KrbCredInfo struct {
	Key       EncryptionKey
	PRealm    *Realm
	PName     *PrincipalName
	Flags     *TicketFlags
	AuthTime  *KerberosTime
	StartTime *KerberosTime
	EndTime   *KerberosTime
	RenewTill *KerberosTime
	SRealm    *Realm
	SName     *PrincipalName
	CAddr     HostAddresses
}

/**
  KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
          pvno            [0] INTEGER (5),
          msg-type        [1] INTEGER (30),
          ctime           [2] KerberosTime OPTIONAL,
          cusec           [3] Microseconds OPTIONAL,
          stime           [4] KerberosTime,
          susec           [5] Microseconds,
          error-code      [6] Int32,
          crealm          [7] Realm OPTIONAL,
          cname           [8] PrincipalName OPTIONAL,
          realm           [9] Realm -- service realm --,
          sname           [10] PrincipalName -- service name --,
          e-text          [11] KerberosString OPTIONAL,
          e-data          [12] OCTET STRING OPTIONAL
  }
*/
type KrbError struct {
	PvNo      int32
	MsgType   int32
	CTime     KerberosTime
	CUSec     int32
	ErrorCode int32
	CRealm    Realm
	CName     PrincipalName
	Realm     Realm
	SName     PrincipalName
	EText     string
	EData     []byte // if KDC_ERR_PREAUTH_REQUIRED, will contain an encoding of a sequence of padata fields
}

func (e KrbError) Error() string {
	return fmt.Sprintf("KRB-ERROR %v: %s", e.ErrorCode, e.EText)
}

/**
  TYPED-DATA      ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
          data-type       [0] Int32,
          data-value      [1] OCTET STRING OPTIONAL
  }
*/
type TypedData struct {
	Elements []TypedDataElement
}

type TypedDataElement struct {
	DataType  int32
	DataValue *[]byte
}

/**
  Error Code                         Value  Meaning

  KDC_ERR_NONE                           0  No error
  KDC_ERR_NAME_EXP                       1  Client's entry in database
                                              has expired
  KDC_ERR_SERVICE_EXP                    2  Server's entry in database
                                              has expired
  KDC_ERR_BAD_PVNO                       3  Requested protocol version
                                              number not supported
  KDC_ERR_C_OLD_MAST_KVNO                4  Client's key encrypted in
                                              old master key
  KDC_ERR_S_OLD_MAST_KVNO                5  Server's key encrypted in
                                              old master key
  KDC_ERR_C_PRINCIPAL_UNKNOWN            6  Client not found in
                                              Kerberos database
  KDC_ERR_S_PRINCIPAL_UNKNOWN            7  Server not found in
                                              Kerberos database
  KDC_ERR_PRINCIPAL_NOT_UNIQUE           8  Multiple principal entries
                                              in database
  KDC_ERR_NULL_KEY                       9  The client or server has a
                                              null key
  KDC_ERR_CANNOT_POSTDATE               10  Ticket not eligible for
                                              postdating
  KDC_ERR_NEVER_VALID                   11  Requested starttime is
                                              later than end time
  KDC_ERR_POLICY                        12  KDC policy rejects request
  KDC_ERR_BADOPTION                     13  KDC cannot accommodate
                                              requested option
  KDC_ERR_ETYPE_NOSUPP                  14  KDC has no support for
                                              encryption type
  KDC_ERR_SUMTYPE_NOSUPP                15  KDC has no support for
                                              checksum type
  KDC_ERR_PADATA_TYPE_NOSUPP            16  KDC has no support for
                                              padata type
  KDC_ERR_TRTYPE_NOSUPP                 17  KDC has no support for
                                              transited type
  KDC_ERR_CLIENT_REVOKED                18  Clients credentials have
                                              been revoked
  KDC_ERR_SERVICE_REVOKED               19  Credentials for server have
                                              been revoked
  KDC_ERR_TGT_REVOKED                   20  TGT has been revoked
  KDC_ERR_CLIENT_NOTYET                 21  Client not yet valid; try
                                              again later
  KDC_ERR_SERVICE_NOTYET                22  Server not yet valid; try
                                              again later
  KDC_ERR_KEY_EXPIRED                   23  Password has expired;
                                              change password to reset
  KDC_ERR_PREAUTH_FAILED                24  Pre-authentication
                                              information was invalid
  KDC_ERR_PREAUTH_REQUIRED              25  Additional pre-
                                              authentication required
  KDC_ERR_SERVER_NOMATCH                26  Requested server and ticket
                                              don't match
  KDC_ERR_MUST_USE_USER2USER            27  Server principal valid for
                                              user2user only
  KDC_ERR_PATH_NOT_ACCEPTED             28  KDC Policy rejects
                                              transited path
  KDC_ERR_SVC_UNAVAILABLE               29  A service is not available
  KRB_AP_ERR_BAD_INTEGRITY              31  Integrity check on
                                              decrypted field failed
  KRB_AP_ERR_TKT_EXPIRED                32  Ticket expired
  KRB_AP_ERR_TKT_NYV                    33  Ticket not yet valid
  KRB_AP_ERR_REPEAT                     34  Request is a replay
  KRB_AP_ERR_NOT_US                     35  The ticket isn't for us
  KRB_AP_ERR_BADMATCH                   36  Ticket and authenticator
                                              don't match
  KRB_AP_ERR_SKEW                       37  Clock skew too great
  KRB_AP_ERR_BADADDR                    38  Incorrect net address
  KRB_AP_ERR_BADVERSION                 39  Protocol version mismatch
  KRB_AP_ERR_MSG_TYPE                   40  Invalid msg type
  KRB_AP_ERR_MODIFIED                   41  Message stream modified
  KRB_AP_ERR_BADORDER                   42  Message out of order
  KRB_AP_ERR_BADKEYVER                  44  Specified version of key is
                                              not available
  KRB_AP_ERR_NOKEY                      45  Service key not available
  KRB_AP_ERR_MUT_FAIL                   46  Mutual authentication
                                              failed
  KRB_AP_ERR_BADDIRECTION               47  Incorrect message direction
  KRB_AP_ERR_METHOD                     48  Alternative authentication
                                              method required
  KRB_AP_ERR_BADSEQ                     49  Incorrect sequence number
                                              in message
  KRB_AP_ERR_INAPP_CKSUM                50  Inappropriate type of
                                              checksum in message
  KRB_AP_PATH_NOT_ACCEPTED              51  Policy rejects transited
                                              path
  KRB_ERR_RESPONSE_TOO_BIG              52  Response too big for UDP;
                                              retry with TCP
  KRB_ERR_GENERIC                       60  Generic error (description
                                              in e-text)
  KRB_ERR_FIELD_TOOLONG                 61  Field is too long for this
                                              implementation
  KDC_ERROR_CLIENT_NOT_TRUSTED          62  Reserved for PKINIT
  KDC_ERROR_KDC_NOT_TRUSTED             63  Reserved for PKINIT
  KDC_ERROR_INVALID_SIG                 64  Reserved for PKINIT
  KDC_ERR_KEY_TOO_WEAK                  65  Reserved for PKINIT
  KDC_ERR_CERTIFICATE_MISMATCH          66  Reserved for PKINIT
  KRB_AP_ERR_NO_TGT                     67  No TGT available to
                                              validate USER-TO-USER
  KDC_ERR_WRONG_REALM                   68  Reserved for future use
  KRB_AP_ERR_USER_TO_USER_REQUIRED      69  Ticket must be for
                                              USER-TO-USER
  KDC_ERR_CANT_VERIFY_CERTIFICATE       70  Reserved for PKINIT
  KDC_ERR_INVALID_CERTIFICATE           71  Reserved for PKINIT
  KDC_ERR_REVOKED_CERTIFICATE           72  Reserved for PKINIT
  KDC_ERR_REVOCATION_STATUS_UNKNOWN     73  Reserved for PKINIT
  KDC_ERR_REVOCATION_STATUS_UNAVAILABLE 74  Reserved for PKINIT
  KDC_ERR_CLIENT_NAME_MISMATCH          75  Reserved for PKINIT
  KDC_ERR_KDC_NAME_MISMATCH             76  Reserved for PKINIT
*/
const (
	KDC_ERR_NONE                = 0
	KDC_ERR_C_PRINCIPAL_UNKNOWN = 6
	KDC_ERR_ETYPE_NOSUPP        = 14
	KDC_ERR_CANNOT_POSTDATE     = 10
	KDC_ERR_NEVER_VALID         = 11
	KRB_AP_ERR_BAD_INTEGRITY    = 31
	KRB_AP_ERR_TKT_EXPIRED      = 32
	KRB_AP_ERR_TKT_NYV          = 33
	KRB_AP_ERR_REPEAT           = 34
	KRB_AP_ERR_BADMATCH         = 36
	KRB_AP_ERR_SKEW             = 37
	KRB_AP_ERR_MSG_TYPE         = 40
	KRB_AP_ERR_BADKEYVER        = 44
	KRB_AP_ERR_NOKEY            = 45
	KRB_ERR_GENERIC             = 60
)

func NewEmptyError(realm Realm, sname PrincipalName) KrbError {
	ctime, usec := KerberosTimeNow()
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
