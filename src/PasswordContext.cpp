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

// STL and Boost
#include <string>

// Kerberos
#include <heimdal/kadm5/admin.h>

// Local
#include "PasswordContext.hpp"
#include "Error.hpp"

namespace kadm5
{

PasswordContext::PasswordContext(
	const string& password,
	const string& client,
	const string& realm,
	const string& host,
	const int port
)	:	Context(client, realm, host, port)
{
	// TODO Require password not empty (to prevent input on tty)
	void* ph = NULL;
	Error::throw_on_error(
		kadm5_init_with_password_ctx(
			*this,
			client.empty() ? NULL : client.c_str(),
			password.c_str(),
			KADM5_ADMIN_SERVICE,
			config_params().get(),
			KADM5_STRUCT_VERSION,
			KADM5_API_VERSION_2,
			&ph
		)
	);
	set_kadm_handle( shared_ptr<void>(ph, kadm5_destroy) );
	
	// Check connection.
	u_int32_t p;
	Error::throw_on_error(
		kadm5_get_privs(*this, &p)
	);
}

} /* namespace kadm5 */
