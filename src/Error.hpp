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

#ifndef ERROR_HPP_
#define ERROR_HPP_

// STL and Boost
#include <string>

// Kerberos
#include <krb5.h>
#include <krb5_err.h>
#include <kadm5/admin.h>
#include <kadm5/kadm5_err.h>


#ifdef DEBUG
	#include <iostream>
	/**
	 * Helper macro to print debug messages. If <code>DEBUG</code> was not
	 * defined on compile time, the messages will be left out.
	 * 
	 * \param	xmsg	The <code>std::string</code> message to print.
	 **/
	#define KADM5_DEBUG(xmsg) \
		kadm5::debug( xmsg )
	namespace kadm5 { void debug(const std::string& msg); }
#else
	#define KADM5_DEBUG(xmsg)
#endif

namespace kadm5
{
	
using std::string;

/**
 * \brief
 * Base class for all exceptions related to Kerberos and KAdmin functions.
 * 
 * It contains an error code member that holds the error number returned by
 * the Kerberos and KAdmin functions. See <krb5_err.h> and <kadm5/kadm5_err.h>
 * for relevant <code>#define</code>s. Use error_code() to retrieve the error
 * number.
 * 
 * \note
 * Some exceptions may return an error code of <code>0</code> if their class
 * does not correspond to a library error. (An example for this is
 * AlreadyExists).
 * 
 * Also, a convenience function throw_on_error() is provided to wrap library
 * function calls. It will throw an appropriate exception if an error code
 * was returned. See throw_on_error()'s documentation for an example.
 **/
class error: public std::exception
{
public:
	/**
	 * Constructs a new instance with the given error code.
	 * 
	 * \param	c	The error's number as defined in <krb5_err.h>
	 * 			or <kadm5/kadm5_err.h>.
	 **/
	explicit error(int32_t c) : _error_code(c) {}
	
	/**
	 * Get this exception's error code as returned by the Kerberos or
	 * KAdmin libraries.
	 * 
	 * \return	The error number as <code>#defined</code> in
	 * 		<krb5_err.h> or <kadm5/kadm5_err.h>.
	 **/
	const int32_t error_code() const { return this->_error_code; }
	
	/**
	 * Helper function to wrap Kerberos and KAdmin library calls and throw
	 * an appropriate exception if an error code was returned.
	 * 
	 * \note
	 * Both, <code>krb5_error_code</code> and <code>kadm5_ret_t</code> are
	 * <code>typedef</code>s of <code>u_int32_t</code>.
	 * 
	 * Usage example:
	 * \code
	 * Context c;
	 * u_int32_t p;
	 * 
	 * try {
	 * 	kadm5::Error::throw_on_error( kadm5_get_privs(c, &p) );
	 * }
	 * catch (UnknownPrincipalError& e) {
	 * 	...
	 * }
	 * \endcode
	 * 
	 * \param	c	The library function's return value.
	 **/
	static void throw_on_error(int32_t c);

private:
	/** Holds the library's error code. */
	int32_t _error_code;
};

/*
 * General errors (of no specific category)
 */
struct bad_handle: public error
	{ bad_handle(int32_t c) : error(c) {} };
struct bad_db: public error
	{ bad_db(int32_t c) : error(c) {} };
struct key_history_mismatch: public error
	{ key_history_mismatch(int32_t c) : error(c) {} };
struct secure_principal_missing: public error
	{ secure_principal_missing(int32_t c) : error(c) {} };
struct salt_prevents_rename: public error
	{ salt_prevents_rename(int32_t c) : error(c) {} };
struct bad_tl_type: public error
	{ bad_tl_type(int32_t c) : error(c) {} };

/*
 * Configuration errors
 */
struct config_error: public error
	{ config_error(int32_t c) : error(c) {} };
struct remote_config_error: public config_error
	{ remote_config_error(int32_t c) : config_error(c) {} };
struct local_config_error: public config_error
	{ local_config_error(int32_t c) : config_error(c) {} };
struct params_missing: public config_error
	{ params_missing(int32_t c) : config_error(c) {} };
struct bad_server: public config_error
	{ bad_server(int32_t c) : config_error(c) {} };

/*
 * Connection errors
 */
struct connection_error: public error
	{ connection_error(int32_t c) : error(c) {} };
struct rpc_error: public connection_error
	{ rpc_error(int32_t c) : connection_error(c) {} };
struct no_server: public connection_error
	{ no_server(int32_t c) : connection_error(c) {} };
struct not_initialized: public connection_error
	{ not_initialized(int32_t c) : connection_error(c) {} };
struct already_initialized: public connection_error
	{ already_initialized(int32_t c) : connection_error(c) {} };
struct bad_pw: public connection_error
	{ bad_pw(int32_t c) : connection_error(c) {} };

/*
 * Authentication errors (missing privileges)
 */
struct auth_missing: public error
	{ auth_missing(int32_t c) : error(c) {} };
struct get_auth_missing: public auth_missing
	{ get_auth_missing(int32_t c) : auth_missing(c) {} };
struct add_auth_missing: public auth_missing
	{ add_auth_missing(int32_t c) : auth_missing(c) {} };
struct modify_auth_missing: public auth_missing
	{ modify_auth_missing(int32_t c) : auth_missing(c) {} };
struct delete_auth_missing: public auth_missing
	{ delete_auth_missing(int32_t c) : auth_missing(c) {} };
struct list_auth_missing: public auth_missing
	{ list_auth_missing(int32_t c) : auth_missing(c) {} };
struct cpw_auth_missing: public auth_missing
	{ cpw_auth_missing(int32_t c) : auth_missing(c) {} };
struct setkey_auth_missing: public auth_missing
	{ setkey_auth_missing(int32_t c) : auth_missing(c) {} };

/*
 * Bad function parameters
 */
struct bad_param: public error
	{ bad_param(int32_t c) : error(c) {} };
struct already_exists: public bad_param
	{ already_exists(int32_t c) : bad_param(c) {} };
struct unknown_principal: public bad_param
	{ unknown_principal(int32_t c) : bad_param(c) {} };
struct unknown_policy: public bad_param
	{ unknown_policy(int32_t c) : bad_param(c) {} };
struct bad_mask: public bad_param
	{ bad_mask(int32_t c) : bad_param(c) {} };
struct bad_char_class: public bad_param
	{ bad_char_class(int32_t c) : bad_param(c) {} };
struct bad_pw_length: public bad_param
	{ bad_pw_length(int32_t c) : bad_param(c) {} };
struct bad_policy: public bad_param
	{ bad_policy(int32_t c) : bad_param(c) {} };
struct bad_principal: public bad_param
	{ bad_principal(int32_t c) : bad_param(c) {} };
struct bad_aux_attr: public bad_param
	{ bad_aux_attr(int32_t c) : bad_param(c) {} };
struct bad_pw_history: public bad_param
	{ bad_pw_history(int32_t c) : bad_param(c) {} };
struct bad_min_pw_life: public bad_param
	{ bad_min_pw_life(int32_t c) : bad_param(c) {} };
struct policy_in_use: public bad_param
	{ policy_in_use(int32_t c) : bad_param(c) {} };
struct principal_protected: public bad_param
	{ principal_protected(int32_t c) : bad_param(c) {} };
struct duplicate_enctype: public bad_param
	{ duplicate_enctype(int32_t c) : bad_param(c) {} };
struct ambiguous_name: public bad_param
	{ ambiguous_name(int32_t c) : bad_param(c) {} };

/*
 * Password quality errors
 */
struct pw_quality_error: public error
	{ pw_quality_error(int32_t c) : error(c) {} };
struct pw_too_short: public pw_quality_error
	{ pw_too_short(int32_t c) : pw_quality_error(c) {} };
struct too_few_char_classes: public pw_quality_error
	{ too_few_char_classes(int32_t c) : pw_quality_error(c) {} };
struct pw_in_dictionary: public pw_quality_error
	{ pw_in_dictionary(int32_t c) : pw_quality_error(c) {} };
struct pw_reuse: public pw_quality_error
	{ pw_reuse(int32_t c) : pw_quality_error(c) {} };
struct too_soon: public pw_quality_error
	{ too_soon(int32_t c) : pw_quality_error(c) {} };

/*
 * Version errors
 */
struct version_error: public error
	{ version_error(int32_t c) : error(c) {} };
struct bad_struct_version: public version_error
	{ bad_struct_version(int32_t c) : version_error(c) {} };
struct old_struct_version: public version_error
	{ old_struct_version(int32_t c) : version_error(c) {} };
struct new_struct_version: public version_error
	{ new_struct_version(int32_t c) : version_error(c) {} };
struct bad_api_version: public version_error
	{ bad_api_version(int32_t c) : version_error(c) {} };
struct old_lib_api: public version_error
	{ old_lib_api(int32_t c) : version_error(c) {} };
struct old_server_api: public version_error
	{ old_server_api(int32_t c) : version_error(c) {} };
struct new_lib_api: public version_error
	{ new_lib_api(int32_t c) : version_error(c) {} };
struct new_server_api: public version_error
	{ new_server_api(int32_t c) : version_error(c) {} };


} /* namespace kadm5 */

#endif /*ERROR_HPP_*/
