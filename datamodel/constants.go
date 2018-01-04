package datamodel

/**
  Error Code                         Value  Meaning

  KDC_ERR_NONE                           0  No error
  KDC_ERR_NAME_EXP                       1  Client's entry in database has expired
  KDC_ERR_SERVICE_EXP                    2  Server's entry in database has expired
  KDC_ERR_BAD_PVNO                       3  Requested protocol version number not supported
  KDC_ERR_C_OLD_MAST_KVNO                4  Client's key encrypted in old master key
  KDC_ERR_S_OLD_MAST_KVNO                5  Server's key encrypted in old master key
  KDC_ERR_C_PRINCIPAL_UNKNOWN            6  Client not found in Kerberos database
  KDC_ERR_S_PRINCIPAL_UNKNOWN            7  Server not found in Kerberos database
  KDC_ERR_PRINCIPAL_NOT_UNIQUE           8  Multiple principal entries in database
  KDC_ERR_NULL_KEY                       9  The client or server has a null key
  KDC_ERR_CANNOT_POSTDATE               10  Ticket not eligible for postdating
  KDC_ERR_NEVER_VALID                   11  Requested starttime is later than end time
  KDC_ERR_POLICY                        12  KDC policy rejects request
  KDC_ERR_BADOPTION                     13  KDC cannot accommodate requested option
  KDC_ERR_ETYPE_NOSUPP                  14  KDC has no support for encryption type
  KDC_ERR_SUMTYPE_NOSUPP                15  KDC has no support for checksum type
  KDC_ERR_PADATA_TYPE_NOSUPP            16  KDC has no support for padata type
  KDC_ERR_TRTYPE_NOSUPP                 17  KDC has no support for transited type
  KDC_ERR_CLIENT_REVOKED                18  Clients credentials have been revoked
  KDC_ERR_SERVICE_REVOKED               19  Credentials for server have been revoked
  KDC_ERR_TGT_REVOKED                   20  TGT has been revoked
  KDC_ERR_CLIENT_NOTYET                 21  Client not yet valid; try again later
  KDC_ERR_SERVICE_NOTYET                22  Server not yet valid; try again later
  KDC_ERR_KEY_EXPIRED                   23  Password has expired; change password to reset
  KDC_ERR_PREAUTH_FAILED                24  Pre-authentication information was invalid
  KDC_ERR_PREAUTH_REQUIRED              25  Additional pre-authentication required
  KDC_ERR_SERVER_NOMATCH                26  Requested server and ticket don't match
  KDC_ERR_MUST_USE_USER2USER            27  Server principal valid for user2user only
  KDC_ERR_PATH_NOT_ACCEPTED             28  KDC Policy rejects transited path
  KDC_ERR_SVC_UNAVAILABLE               29  A service is not available
  KRB_AP_ERR_BAD_INTEGRITY              31  Integrity check on decrypted field failed
  KRB_AP_ERR_TKT_EXPIRED                32  Ticket expired
  KRB_AP_ERR_TKT_NYV                    33  Ticket not yet valid
  KRB_AP_ERR_REPEAT                     34  Request is a replay
  KRB_AP_ERR_NOT_US                     35  The ticket isn't for us
  KRB_AP_ERR_BADMATCH                   36  Ticket and authenticator don't match
  KRB_AP_ERR_SKEW                       37  Clock skew too great
  KRB_AP_ERR_BADADDR                    38  Incorrect net address
  KRB_AP_ERR_BADVERSION                 39  Protocol version mismatch
  KRB_AP_ERR_MSG_TYPE                   40  Invalid msg type
  KRB_AP_ERR_MODIFIED                   41  Message stream modified
  KRB_AP_ERR_BADORDER                   42  Message out of order
  KRB_AP_ERR_BADKEYVER                  44  Specified version of key is not available
  KRB_AP_ERR_NOKEY                      45  Service key not available
  KRB_AP_ERR_MUT_FAIL                   46  Mutual authentication failed
  KRB_AP_ERR_BADDIRECTION               47  Incorrect message direction
  KRB_AP_ERR_METHOD                     48  Alternative authentication method required
  KRB_AP_ERR_BADSEQ                     49  Incorrect sequence number in message
  KRB_AP_ERR_INAPP_CKSUM                50  Inappropriate type of checksum in message
  KRB_AP_PATH_NOT_ACCEPTED              51  Policy rejects transited path
  KRB_ERR_RESPONSE_TOO_BIG              52  Response too big for UDP; retry with TCP
  KRB_ERR_GENERIC                       60  Generic error (description in e-text)
  KRB_ERR_FIELD_TOOLONG                 61  Field is too long for this implementation
  KDC_ERROR_CLIENT_NOT_TRUSTED          62  Reserved for PKINIT
  KDC_ERROR_KDC_NOT_TRUSTED             63  Reserved for PKINIT
  KDC_ERROR_INVALID_SIG                 64  Reserved for PKINIT
  KDC_ERR_KEY_TOO_WEAK                  65  Reserved for PKINIT
  KDC_ERR_CERTIFICATE_MISMATCH          66  Reserved for PKINIT
  KRB_AP_ERR_NO_TGT                     67  No TGT available to validate USER-TO-USER
  KDC_ERR_WRONG_REALM                   68  Reserved for future use
  KRB_AP_ERR_USER_TO_USER_REQUIRED      69  Ticket must be for USER-TO-USER
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
	KDC_ERR_S_PRINCIPAL_UNKNOWN = 7
	KDC_ERR_POLICY              = 12
	KDC_ERR_ETYPE_NOSUPP        = 14
	KDC_ERR_CANNOT_POSTDATE     = 10
	KDC_ERR_NEVER_VALID         = 11
	KDC_ERR_PADATA_TYPE_NOSUPP  = 16
	KDC_ERR_TGT_REVOKED         = 20
	KDC_ERR_PREAUTH_REQUIRED    = 25
	KRB_AP_ERR_BAD_INTEGRITY    = 31
	KRB_AP_ERR_TKT_EXPIRED      = 32
	KRB_AP_ERR_TKT_NYV          = 33
	KRB_AP_ERR_REPEAT           = 34
	KRB_AP_ERR_BADMATCH         = 36
	KRB_AP_ERR_SKEW             = 37
	KRB_AP_ERR_MSG_TYPE         = 40
	KRB_AP_ERR_MODIFIED         = 41
	KRB_AP_ERR_BADKEYVER        = 44
	KRB_AP_ERR_NOKEY            = 45
	KRB_AP_ERR_INAPP_CKSUM      = 50
	KRB_ERR_GENERIC             = 60
)

/** LastReq lr-type values

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
	APOptions flag values
 */
const (
	AP_FLAG_RESERVED        = 0
	AP_FLAG_USE_SESSION_KEY = 1
	AP_FLAG_MUTUAL_REQUIRED = 2
)

/**
	KdcOptions flag values
 */
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
	KDC_FLAG_VALIDATE       = 31
)

/**
	TicketFlags flag values
 */

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

/**
	PrincipalName types
*/
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

const (
	KRBTGT = "krbtgt"
	KERBEROS_TIME_FORMAT = "20060102150405Z"
)
