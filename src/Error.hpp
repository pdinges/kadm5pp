#ifndef ERROR_HPP_
#define ERROR_HPP_

#define KADM5_OK		(0L)
#define KRB5_OK			(0L)
#define KADM5_AMBIGUOUS_KEY	(43500000L)

#include <krb5.h>
#include <krb5_err.h>
#include <heimdal/kadm5/admin.h>
#include <heimdal/kadm5/kadm5_err.h>

namespace KAdm5
{

class Error {
public:
	Error(int32_t c) : _errorCode(c) {}
	int32_t getErrorCode() { return this->_errorCode; }
	
	static void checkReturnVal(int32_t);

private:
	int32_t _errorCode;	// kadm5_ret_t and krb5_error_code are just typedefs of int32_t
};

// TODO Maybe rename classes and remove Error suffix?
struct AuthError:		public Error { AuthError(int32_t c) : Error(c) {} };
struct GetAuthError:		public AuthError { GetAuthError(int32_t c) : AuthError(c) {} };
struct AddAuthError:		public AuthError { AddAuthError(int32_t c) : AuthError(c) {} };
struct ModifyAuthError:		public AuthError { ModifyAuthError(int32_t c) : AuthError(c) {} };
struct DeleteAuthError:		public AuthError { DeleteAuthError(int32_t c) : AuthError(c) {} };
struct ListAuthError:		public AuthError { ListAuthError(int32_t c) : AuthError(c) {} };
struct ChangePasswordAuthError:	public AuthError { ChangePasswordAuthError(int32_t c) : AuthError(c) {} };

struct ConfigError:		public Error { ConfigError(int32_t c) : Error(c) {} };
struct DBError:			public ConfigError { DBError(int32_t c) : ConfigError(c) {} };

struct ParamError:		public Error { ParamError(int32_t c) : Error(c) {} };
struct UnknownPrincipalError:	public ParamError { UnknownPrincipalError(int32_t c) : ParamError(c) {} };
struct UnknownPolicyError:	public ParamError { UnknownPolicyError(int32_t c) : ParamError(c) {} };
struct MaskError:		public ParamError { MaskError(int32_t c) : ParamError(c) {} };
struct ClassError:		public ParamError { ClassError(int32_t c) : ParamError(c) {} };
struct LengthError:		public ParamError { LengthError(int32_t c) : ParamError(c) {} };
struct PolicyError:		public ParamError { PolicyError(int32_t c) : ParamError(c) {} };
struct PrincipalError:		public ParamError { PrincipalError(int32_t c) : ParamError(c) {} };
struct AuxAttributeError:	public ParamError { AuxAttributeError(int32_t c) : ParamError(c) {} };
struct HistoryError:		public ParamError { HistoryError(int32_t c) : ParamError(c) {} };
struct MinPasswordLifeError:	public ParamError { MinPasswordLifeError(int32_t c) : ParamError(c) {} };
struct AmbiguousKeyError:	public ParamError { AmbiguousKeyError(int32_t c) : ParamError(c) {} };
struct AlreadyExists:		public ParamError { AlreadyExists(int32_t c) : ParamError(c) {} };

struct PwQualityError:		public Error { PwQualityError(int32_t c) : Error(c) {} };
struct PwTooShortError:		public PwQualityError { PwTooShortError(int32_t c) : PwQualityError(c) {} };
struct PwClassError:		public PwQualityError { PwClassError(int32_t c) : PwQualityError(c) {} };
struct DictionaryPwError:	public PwQualityError { DictionaryPwError(int32_t c) : PwQualityError(c) {} };

struct VersionError:		public Error { VersionError(int32_t c) : Error(c) {} };
struct StructVersionError:	public VersionError { StructVersionError(int32_t c) : VersionError(c) {} };
struct ApiVersionError:		public VersionError { ApiVersionError(int32_t c) : VersionError(c) {} };

struct RpcError:		public Error { RpcError(int32_t c) : Error(c) {} };
struct NoServerError:		public Error { NoServerError(int32_t c) : Error(c) {} };


// TODO Add classes for the following kadmin errors:
//#define KADM5_DUP                                (43787527L)
//#define KADM5_BAD_HIST_KEY                       (43787530L)
//#define KADM5_NOT_INIT                           (43787531L)
//#define KADM5_PASS_REUSE                         (43787545L)
//#define KADM5_PASS_TOOSOON                       (43787546L)
//#define KADM5_POLICY_REF                         (43787547L)
//#define KADM5_INIT                               (43787548L)
//#define KADM5_BAD_PASSWORD                       (43787549L)
//#define KADM5_PROTECT_PRINCIPAL                  (43787550L)
//#define KADM5_BAD_SERVER_HANDLE                  (43787551L)
//#define KADM5_SECURE_PRINC_MISSING               (43787560L)
//#define KADM5_NO_RENAME_SALT                     (43787561L)
//#define KADM5_BAD_CLIENT_PARAMS                  (43787562L)
//#define KADM5_BAD_SERVER_PARAMS                  (43787563L)
//#define KADM5_BAD_TL_TYPE                        (43787566L)
//#define KADM5_MISSING_CONF_PARAMS                (43787567L)
//#define KADM5_BAD_SERVER_NAME                    (43787568L)

// TODO Add classes for krb5 errors.

}

#endif /*ERROR_HPP_*/
