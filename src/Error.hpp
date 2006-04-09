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
#include <heimdal/kadm5/admin.h>
#include <heimdal/kadm5/kadm5_err.h>


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
 * 
 * \todo 	Inherit from std::exception and provide a string translation
 * 		for the error code (use library error tables).
 **/
class Error
{
public:
	/**
	 * Constructs a new Error with the given error code.
	 * 
	 * \param	c	The error's number as defined in <krb5_err.h>
	 * 			or <kadm5/kadm5_err.h>.
	 **/
	explicit Error(int32_t c) : _error_code(c) {}
	
	/**
	 * Get this exception's error code as returned by the Kerberos or
	 * KAdmin libraries.
	 * 
	 * \return	The error number as <code>#defined</code> in
	 * 		<krb5_err.h> or <kadm5/kadm5_err.h>.
	 **/
	int32_t error_code() const { return this->_error_code; }
	
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

// TODO Maybe rename classes and remove Error suffix?

// TODO Rename to auth_missing, get_auth_missing, ...
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

} /* namespace kadm5 */

#endif /*ERROR_HPP_*/
