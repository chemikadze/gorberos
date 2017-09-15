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
type TicketFlags struct {
	Data KerberosFlags
}

// TODO
func (TicketFlags) Decode() DecodedTicketFlags {
	return DecodedTicketFlags{}
}

type DecodedTicketFlags struct {
	// TBD
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
	PvNo    int32
	MsgType int64
	PaData  []PaData
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
	KdcOptions           KdcOptions
	CName                PrincipalName
	Realm                Realm
	SName                PrincipalName
	From                 *KerberosTime
	Till                 KerberosTime
	RTime                *KerberosTime
	NoOnce               uint32
	EType                []int32
	Addresses            HostAddresses
	EncAuthorizationData *EncryptedData
	AdditionalTickets    []Ticket
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
type KdcOptions struct {
	Data KerberosFlags
}

// TODO
func (KdcOptions) Decode() DecodedKdcOptions {
	return DecodedKdcOptions{}
}

type DecodedKdcOptions struct {
}

/**
  AS-REQ          ::= [APPLICATION 10] KDC-REQ
*/
type AsReq struct {
	KdcReq
}

/**
  AS-REP          ::= [APPLICATION 11] KDC-REP
*/
type AsRep struct {
	KdcRep
}

/**
  TGS-REQ         ::= [APPLICATION 12] KDC-REQ
*/
type TgsReq struct {
	KdcReq
}

func (TgsReq) PaType() int32 {
	return PA_TGS_REQ
}

/**
  TGS-REP         ::= [APPLICATION 13] KDC-REP
*/
type TgsRep struct {
	KdcRep
}

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
type EncAsRepPart struct {
	EncKDCRepPart
}

/**
  EncTGSRepPart   ::= [APPLICATION 26] EncKDCRepPart
*/
type EncTGSRepPart struct {
	EncKDCRepPart
}

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
	NoNCE         uint32
	KeyExpiration *KerberosTime
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
type LastReq struct {
	LrType  int32
	LrValue KerberosTime
}

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
	PvNo          int32
	MsgType       int32
	ApOptions     ApOptions
	Authenticator EncryptedData
}

/**
  APOptions       ::= KerberosFlags
          -- reserved(0),
          -- use-session-key(1),
          -- mutual-required(2)
*/
type ApOptions struct {
	Data KerberosFlags
}

func (ApOptions) Decode() DecodedApOptions {
	return DecodedApOptions{}
}

type DecodedApOptions struct {
}

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
	CUSec             uint32
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
	EData     []byte
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
