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

// Local
#include "Error.hpp"

#ifdef DEBUG
	#include <iostream>
	void kadm5::debug(const std::string& msg) { std::cout << msg; }
#endif


namespace kadm5
{

void error::throw_on_error(int32_t c)
{
	switch(c) {
		case 0L:
		case KRB5KDC_ERR_NONE:
			return;
		case KADM5_FAILURE:
			throw error(c);


		// KAdmin general errors
		case KADM5_BAD_SERVER_HANDLE:
			throw bad_handle(c);
		case KADM5_BAD_DB:
			throw bad_db(c);
		case KADM5_BAD_HIST_KEY:
			throw key_history_mismatch(c);
		case KADM5_SECURE_PRINC_MISSING:
			throw secure_principal_missing(c);
		case KADM5_NO_RENAME_SALT:
			throw salt_prevents_rename(c);
		case KADM5_BAD_TL_TYPE:
			throw bad_tl_type(c);


		// KAdmin config errors
		case KADM5_BAD_CLIENT_PARAMS:
			throw remote_config_error(c);
		case KADM5_BAD_SERVER_PARAMS:
			throw local_config_error(c);
		case KADM5_MISSING_CONF_PARAMS:
			throw params_missing(c);
		case KADM5_BAD_SERVER_NAME:
			throw bad_server(c);


		// KAdmin connection errors
		case KADM5_RPC_ERROR:
			throw rpc_error(c);
		case KADM5_NO_SRV:
			throw no_server(c);
		case KADM5_NOT_INIT:
			throw not_initialized(c);
		case KADM5_INIT:
			throw already_initialized(c);
		case KADM5_BAD_PASSWORD:
			throw bad_pw(c);


		// KAdmin authentication errors
		case KADM5_AUTH_INSUFFICIENT:
			throw auth_missing(c);
		case KADM5_AUTH_GET:
			throw get_auth_missing(c);
		case KADM5_AUTH_ADD:
			throw add_auth_missing(c);
		case KADM5_AUTH_MODIFY:
			throw modify_auth_missing(c);
		case KADM5_AUTH_DELETE:
			throw delete_auth_missing(c);
		case KADM5_AUTH_LIST:
			throw list_auth_missing(c);
		case KADM5_AUTH_CHANGEPW:
			throw cpw_auth_missing(c);
#ifdef KADM5_AUTH_SETKEY
		case KADM5_AUTH_SETKEY:
			throw setkey_auth_missing(c);
#endif
		

		// KAdmin function parameter errors
		case KADM5_DUP:
			throw already_exists(c);
		case KADM5_UNK_PRINC:
			throw unknown_principal(c);
		case KADM5_UNK_POLICY:
			throw unknown_policy(c);
		case KADM5_BAD_MASK:
			throw bad_mask(c);
		case KADM5_BAD_CLASS:
			throw bad_char_class(c);
		case KADM5_BAD_LENGTH:
			throw bad_pw_length(c);
		case KADM5_BAD_POLICY:
			throw bad_policy(c);
		case KADM5_BAD_PRINCIPAL:
			throw bad_principal(c);
		case KADM5_BAD_AUX_ATTR:
			throw bad_aux_attr(c);
		case KADM5_BAD_HISTORY:
			throw bad_pw_history(c);
		case KADM5_BAD_MIN_PASS_LIFE:
			throw bad_min_pw_life(c);
		case KADM5_POLICY_REF:
			throw policy_in_use(c);
		case KADM5_PROTECT_PRINCIPAL:
			throw principal_protected(c);
#ifdef KADM5_SETKEY_DUP_ENCTYPES
		case KADM5_SETKEY_DUP_ENCTYPES:
			throw duplicate_enctype(c);
#endif


		// KAdmin password quality errors
		case KADM5_PASS_Q_TOOSHORT:
			throw pw_too_short(c);
		case KADM5_PASS_Q_CLASS:
			throw too_few_char_classes(c);
		case KADM5_PASS_Q_DICT:
			throw pw_in_dictionary(c);
		case KADM5_PASS_REUSE:
			throw pw_reuse(c);
		case KADM5_PASS_TOOSOON:
			throw too_soon(c);


		// KAdmin version errors
		case KADM5_BAD_STRUCT_VERSION:
			throw bad_struct_version(c);
		case KADM5_OLD_STRUCT_VERSION:
			throw old_struct_version(c);
		case KADM5_NEW_STRUCT_VERSION:
			throw new_struct_version(c);
		case KADM5_BAD_API_VERSION:
			throw bad_api_version(c);
		case KADM5_OLD_LIB_API_VERSION:
			throw old_lib_api(c);
		case KADM5_OLD_SERVER_API_VERSION:
			throw old_server_api(c);
		case KADM5_NEW_LIB_API_VERSION:
			throw new_lib_api(c);
		case KADM5_NEW_SERVER_API_VERSION:
			throw new_server_api(c);


		// Kerberos 5 and system errors
		// (actually returned values only --- see Kerberos 5 API for
		// details on which function may return which value).

		// Treat malformed principal name errors like
		// KADM5_BAD_PRINCIPAL
		case KRB5_PARSE_MALFORMED:
			throw bad_principal(c);
		case ENOMEM:
			// FIXME Have a preallocated instance to throw on
			// memory shortage. How does this affect thread-
			// safety?
			throw std::bad_alloc();

		default:
			throw error(c);
	}
}


} /* namespace kadm5 */
