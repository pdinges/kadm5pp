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
#include <cstring>
#include <memory>
#include <string>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>

// Kerberos
#include <krb5.h>
#include <heimdal/kadm5/admin.h>

// Local
#include "Context.hpp"
#include "Error.hpp"

namespace kadm5
{
	
using boost::shared_ptr;
using std::string;


Context::Context(
		const string& client,
		const string& realm,
		const string& host,
		const int port
	) :
		_kadm_handle(),
		_krb_context(),
		_config_params( create_config_params(realm, host, port) ),
		_client(client)
{
	KADM5_DEBUG("Context::Context(): Constructing...\n");
	krb5_context_data* pc = NULL;
	Error::throw_on_error( krb5_init_context(&pc) );
	_krb_context.reset(pc, krb5_free_context);
	
	if (!realm.empty()) {
		Error::throw_on_error(
			krb5_set_default_realm(
				_krb_context.get(),
				realm.c_str()
			)
		);
	}
}



shared_ptr<kadm5_config_params> create_config_params(
	const string& realm,
	const string& host,
	const int port
)
{
	KADM5_DEBUG("create_config_params()\n");
	// Ensure kadm5_config_params structure is deleted properly.
	shared_ptr<kadm5_config_params> pret(
		new kadm5_config_params, delete_config_params
	);

	// Structure 0-setting is important for deletion.
	// (Unused pointers must be NULL.)
	memset(pret.get(), 0, sizeof(kadm5_config_params));
	
	if (!realm.empty()) {
		pret->realm = new char[realm.length() + 1];
		realm.copy(pret->realm, string::npos);
		pret->realm[realm.length()] = 0;
		
		pret->mask | KADM5_CONFIG_REALM;
	}		

	if (!host.empty()) {
		pret->admin_server = new char[host.length() + 1];
		host.copy(pret->admin_server, string::npos);
		pret->admin_server[host.length()] = 0;
		
		pret->mask | KADM5_CONFIG_ADMIN_SERVER;
	}		
	
	if (port > 0) {
		pret->kadmind_port = port;
		pret->mask |= KADM5_CONFIG_KADMIND_PORT;
	}
	
	return pret;
}


void delete_config_params(kadm5_config_params* pp)
{
	KADM5_DEBUG("delete_config_params()\n");
	// Unconditional delete works since uninitialized pointers are NULL.
	delete[] pp->realm;
	delete[] pp->admin_server;
	delete pp;
}


void delete_krb5_principal(shared_ptr<const Context> pc, krb5_principal pp)
{
	KADM5_DEBUG("delete_krb5_principal()\n");
	krb5_free_principal(*pc, pp);
}

void delete_kadm5_principal_ent(
	shared_ptr<const Context> pc,
	kadm5_principal_ent_t pe
) {
	KADM5_DEBUG("delete_kadm5_principal_ent()\n");
	kadm5_free_principal_ent(*pc, pe);
}


// Use a shared pointer to Context so it won't cease to exist while still
// needed for deletion.
shared_ptr<krb5_principal_data> parse_name(
	shared_ptr<const Context> pc,
	const string& name
) {
	krb5_principal_data* ptmp = NULL;

	Error::throw_on_error( krb5_parse_name(*pc, name.c_str(), &ptmp) );
	shared_ptr<krb5_principal_data> pret(
		ptmp, boost::bind(delete_krb5_principal, pc, _1)
	);
	
	return pret;
}


string unparse_name(shared_ptr<const Context> pc, krb5_const_principal pp)
{
	char* tmp = NULL;
	
	Error::throw_on_error( krb5_unparse_name(*pc, pp, &tmp) );
	std::auto_ptr<char> name(tmp);
	
	return string(name.get());	
}

} /* namespace kadm5 */
