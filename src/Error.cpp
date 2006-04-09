/******************************************************************************
 *                                                                            *
 *  Copyright (c) 2006 Peter Dinges <me@elwedgo.de>                           *
 *  All rights reserved.                                                      *
 *                                                                            *
 *  Redistribution and use in source and binary forms, with or without        *
 *  modification, are permitted provided that the following conditions        *
 *  are met:                                                                  *
 *                                                                            *
 *  1. Redistributions of source code must retain the above copyright         *
 *     notice, this list of conditions and the following disclaimer.          *
 *                                                                            *
 *  2. Redistributions in binary form must reproduce the above copyright      *
 *     notice, this list of conditions and the following disclaimer in the    *
 *     documentation and/or other materials provided with the distribution.   *
 *                                                                            *
 *  3. The name of the author may not be used to endorse or promote products  *
 *     derived from this software without specific prior written permission.  *
 *                                                                            *
 *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR      *
 *  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES *
 *  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.   *
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,          *
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT  *
 *  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, *
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY     *
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT       *
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF  *
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.         *
 *                                                                            *
 *****************************************************************************/
/* $Id$ */

#include "Error.hpp"

#ifdef DEBUG
	void kadm5::debug(const std::string& msg) { std::cout << msg; }
#endif


namespace kadm5
{

void Error::throw_on_error(int32_t c)
{
	switch(c) {
		case 0L:
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


} /* namespace kadm5 */
