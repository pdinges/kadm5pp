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
#include <vector>
#include <boost/shared_ptr.hpp>

// Kerberos
#include <krb5.h>
#include <heimdal/kadm5/admin.h>
#include <heimdal/kadm5/kadm5_err.h>

// Local
#include "CCacheContext.hpp"
#include "Connection.hpp"
#include "Context.hpp"
#include "Error.hpp"
#include "PasswordContext.hpp"
#include "Principal.hpp"


namespace kadm5
{

using boost::shared_ptr;
using std::string;
using std::vector;

shared_ptr<Connection> Connection::from_password(
	const string& password,
	const string& client,
	const string& realm,
	const string& host,
	const int port
) {
	shared_ptr<Context> pc(
		new PasswordContext(password, client, realm, host, port)
	);

	return shared_ptr<Connection>( new Connection(pc) );
}


shared_ptr<Connection> Connection::from_credential_cache(
	const string& ccname,
	const string& realm,
	const string& host,
	const int port
) {
	shared_ptr<Context> pc(
		new CCacheContext(ccname, realm, host, port)
	);
	
	return shared_ptr<Connection>( new Connection(pc) );
}



Connection::Connection(shared_ptr<Context> context)
	:	_context(context)
{
}


shared_ptr<Principal> Connection::create_principal(
	const string& name,
	const string& password
) const
{
	if (!may_add()) {
		throw add_auth_missing(KADM5_AUTH_ADD);
	}
	
	shared_ptr< vector<string> > pexisting( list_principals(name) );
	
	// A bad principal name will throw an exception in list_principals(),
	// so this test will work correctly.
	if (!pexisting->empty()) {
		throw already_exists(KADM5_DUP);
	}

	shared_ptr<Principal> pp(
		new Principal(_context, name, password)
	);
	
	return pp;
}


void Connection::delete_principal(const string& id) const
{
	Principal p(_context, id);
	error::throw_on_error(
		kadm5_delete_principal(*_context, p._id.get())
	);
}


shared_ptr<Principal> Connection::get_principal(const string& id) const
{
	if (!may_get()) {
		throw get_auth_missing(KADM5_AUTH_GET);
	}
	
	shared_ptr< vector<string> > pcandidates( list_principals(id) );
	
	// Unambiguous description suffices.
	if (pcandidates->size() == 1) {
		shared_ptr<Principal> pret(
			new Principal(_context, (*pcandidates)[0])
		);
		return pret;
	}
	else if (pcandidates->size() < 1) {
		throw unknown_principal(KADM5_UNK_PRINC);
	}
	else {
		throw ambiguous_name(0);
	}
}


shared_ptr< vector< shared_ptr<Principal> > > Connection::get_principals(
	const string& filter
) const {
	if (!may_get()) {
		throw add_auth_missing(KADM5_AUTH_GET);
	}
	
	shared_ptr< vector<string> > pnames( list_principals(filter) );
	
	shared_ptr< vector< shared_ptr<Principal> > > pret(
		new vector< shared_ptr<Principal> >
	);
	pret->reserve(pnames->size());
	
	for (
		vector<string>::const_iterator it = pnames->begin();
		it != pnames->end();
		it++
	) {
		pret->push_back(
			shared_ptr<Principal>(new Principal(_context, *it))
		);
	}
	
	return pret;
}


shared_ptr< vector<string> > Connection::list_principals(
	const string& filter
) const {
	if (!may_list()) {
		throw list_auth_missing(KADM5_AUTH_LIST);
	}

	char** list = NULL;
	int count = 0;
	
	try {
		error::throw_on_error(
			kadm5_get_principals(
				*_context,
				filter.c_str(),
				&list,
				&count
			)
		);
		
		// Initialize vector with the list of principal names
		// (treat char** pointer as iterator).
		shared_ptr< vector<string> > pret(
			new vector<string>(list, list + count)
		);
	
		return pret;
	} catch (...) {
		if (list) {
			kadm5_free_name_list(*_context, list, &count);
		}
		throw;
	}
}


const bool Connection::has_privilege(u_int32_t flags) const
{
	u_int32_t p;

	error::throw_on_error(
		kadm5_get_privs(*_context, &p)
	);
	
	return (flags & p) == flags;
}


} /* namespace kadm5 */
