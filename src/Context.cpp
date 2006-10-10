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
#include <cstdlib>
#include <cstring>
#include <string>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>

// Kerberos
#include <krb5.h>
#include <kadm5/admin.h>

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
	KADM5_DEBUG("Context(): Constructing...\n");
	krb5_context_data* pc = NULL;
	error::throw_on_error( krb5_init_context(&pc) );
	_krb_context.reset(pc, krb5_free_context);
	
	if (!realm.empty()) {
		error::throw_on_error(
			krb5_set_default_realm(
				_krb_context.get(),
				realm.c_str()
			)
		);
	}
}


const string Context::client() const
{
	if (_client.empty()) {
		krb5_principal_data* pdefp = NULL;
		
		try {
			error::throw_on_error(
				krb5_get_default_principal(
					_krb_context.get(),
					&pdefp
				)
			);
			
			char* ptmps = NULL;
			error::throw_on_error(
				krb5_unparse_name(
					_krb_context.get(),
					pdefp,
					&ptmps
				)
			);
			string name( ptmps );

			free(ptmps);
			krb5_free_principal(_krb_context.get(), pdefp);
			
			// FIXME Is this always correct?
			if (name.find("/") == string::npos) {
				if (name.find("@") == string::npos) {
					name += "/admin";
				}
				else {
					name.insert(name.find("@"), "/admin");
				}
			}
			
			return name;
		}
		catch(...) {
			krb5_free_principal(_krb_context.get(), pdefp);
			throw;
		}
	}
	else {
		return _client.find("@") == string::npos ?
			_client + "@" + realm():
			_client;
	}
}


const string Context::realm() const
{
	if (_config_params->mask & KADM5_CONFIG_REALM) {
		return _config_params->realm;
	}
	else {
		char* ptmp = NULL;
		error::throw_on_error(
			krb5_get_default_realm(_krb_context.get(), &ptmp)
		);
		shared_ptr<char> pr( ptmp, free );
		
		return pr.get();
	}
}


const string Context::host() const
{
	if (_config_params->mask & KADM5_CONFIG_ADMIN_SERVER) {
		return _config_params->admin_server;
	}
	else {
		const char* ps = krb5_config_get_string_default(
					_krb_context.get(),
					NULL,
					NULL,
					"realms",
					realm().c_str(),
					"admin_server",
					NULL
				);
		
		// "admin_server" config key must exist since construction
		// would have thrown an exception otherwise (no admin server
		// known).
		assert(ps != NULL);
		string s(ps);
		
		return s.substr(0, s.rfind(":"));
	}
}


const int Context::port() const {
	if (	(_config_params->mask & KADM5_CONFIG_ADMIN_SERVER) &&
		(host().rfind(":") != string::npos)
	) {
		string h = host();
		
		// This will deliver a correct port since the construction
		// would have failed otherwise.
		return atoi( h.substr(h.rfind(":")).c_str() );
	}
	else if (_config_params->mask & KADM5_CONFIG_KADMIND_PORT) {
		return _config_params->kadmind_port;
	}
	else {
		return 749;
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


shared_ptr<kadm5_principal_ent_rec> copy_kadm5_principal_ent(
	shared_ptr<const Context> pc,
	const kadm5_principal_ent_t pp
)
{
	KADM5_DEBUG("copy_kadm5_principal_ent()\n");

	shared_ptr<kadm5_principal_ent_rec> pcopy(
		new kadm5_principal_ent_rec,
		boost::bind(delete_kadm5_principal_ent, pc, _1)
	);
	memcpy(pcopy.get(), pp, sizeof(kadm5_principal_ent_rec));
	
	// Ensure nothing gets deleted if an exception is thrown.
	pcopy->principal = NULL;
	pcopy->mod_name = NULL;
	pcopy->policy = NULL;
	pcopy->n_tl_data = 0;
	pcopy->n_key_data = 0;
	pcopy->tl_data = NULL;
	pcopy->key_data = NULL;

	krb5_copy_principal(*pc, pp->principal, &pcopy->principal);
	krb5_copy_principal(*pc, pp->mod_name, &pcopy->mod_name);
	
	pcopy->policy = new char[strlen(pp->policy) + 1];
	strcpy(pp->policy, pcopy->policy);
	
	return pcopy;
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

	error::throw_on_error( krb5_parse_name(*pc, name.c_str(), &ptmp) );
	shared_ptr<krb5_principal_data> pret(
		ptmp, boost::bind(delete_krb5_principal, pc, _1)
	);
	
	return pret;
}


string unparse_name(shared_ptr<const Context> pc, krb5_const_principal pp)
{
	char* tmp = NULL;
	
	error::throw_on_error( krb5_unparse_name(*pc, pp, &tmp) );
	shared_ptr<char> name(tmp, free);
	
	return string(name.get());	
}

} /* namespace kadm5 */
