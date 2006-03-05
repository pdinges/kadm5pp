#include "Error.hpp"

namespace KAdm5
{


void Error::checkReturnVal(int32_t c)
{
	switch(c) {
		case KRB5_OK:
			return;

		case KADM5_AUTH_INSUFFICIENT:
			throw AuthError(c);
		case KADM5_AUTH_GET:
			throw GetAuthError(c);
		case KADM5_AUTH_ADD:
			throw AddAuthError(c);
		case KADM5_AUTH_MODIFY:
			throw ModifyAuthError(c);
		case KADM5_AUTH_DELETE:
			throw DeleteAuthError(c);
		case KADM5_AUTH_LIST:
			throw ListAuthError(c);
		case KADM5_AUTH_CHANGEPW:
			throw ChangePasswordAuthError(c);

		case KADM5_UNK_PRINC:
			throw UnknownPrincipalError(c);
		case KADM5_UNK_POLICY:
			throw UnknownPolicyError(c);
		case KADM5_BAD_MASK:
			throw MaskError(c);
		case KADM5_BAD_CLASS:
			throw ClassError(c);
		case KADM5_BAD_LENGTH:
			throw LengthError(c);
		case KADM5_BAD_POLICY:
			throw PolicyError(c);
		case KADM5_BAD_PRINCIPAL:
			throw PrincipalError(c);
		case KADM5_BAD_AUX_ATTR:
			throw AuxAttributeError(c);
		case KADM5_BAD_HISTORY:
			throw HistoryError(c);
		case KADM5_BAD_MIN_PASS_LIFE:
			throw MinPasswordLifeError(c);

		case KADM5_PASS_Q_TOOSHORT:
			throw PwTooShortError(c);
		case KADM5_PASS_Q_CLASS:
			throw PwClassError(c);
		case KADM5_PASS_Q_DICT:
			throw DictionaryPwError(c);

		case KADM5_BAD_STRUCT_VERSION:
		case KADM5_OLD_STRUCT_VERSION:
		case KADM5_NEW_STRUCT_VERSION:
			throw StructVersionError(c);
		case KADM5_BAD_API_VERSION:
		case KADM5_OLD_LIB_API_VERSION:
		case KADM5_OLD_SERVER_API_VERSION:
		case KADM5_NEW_LIB_API_VERSION:
		case KADM5_NEW_SERVER_API_VERSION:
			throw ApiVersionError(c);

		case KADM5_FAILURE:
			throw Error(c);
		case KADM5_BAD_DB:
			throw DBError(c);
//		case KADM5_:
//			throw Error(c);

// TODO Add cases for the following error values:		
//#define KADM5_BAD_DB                             (43787526L)
//#define KADM5_DUP                                (43787527L)
//#define KADM5_RPC_ERROR                          (43787528L)
//#define KADM5_NO_SRV                             (43787529L)
//#define KADM5_BAD_HIST_KEY                       (43787530L)
//#define KADM5_NOT_INIT                           (43787531L)
//
//#define KADM5_PASS_REUSE                         (43787545L)
//#define KADM5_PASS_TOOSOON                       (43787546L)
//#define KADM5_POLICY_REF                         (43787547L)
//#define KADM5_INIT                               (43787548L)
//#define KADM5_BAD_PASSWORD                       (43787549L)
//#define KADM5_PROTECT_PRINCIPAL                  (43787550L)
//#define KADM5_BAD_SERVER_HANDLE                  (43787551L)
//
//#define KADM5_SECURE_PRINC_MISSING               (43787560L)
//#define KADM5_NO_RENAME_SALT                     (43787561L)
//#define KADM5_BAD_CLIENT_PARAMS                  (43787562L)
//#define KADM5_BAD_SERVER_PARAMS                  (43787563L)
//#define KADM5_BAD_TL_TYPE                        (43787566L)
//#define KADM5_MISSING_CONF_PARAMS                (43787567L)
//#define KADM5_BAD_SERVER_NAME                    (43787568L)

		default:
			throw Error(c);
	}
}


}
