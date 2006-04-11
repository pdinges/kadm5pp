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

#ifndef CONNECTION_HPP_
#define CONNECTION_HPP_

// STL and Boost
#include <string>
#include <vector>
#include <boost/shared_ptr.hpp>

// Kerberos
#include <krb5.h>
#include <heimdal/kadm5/admin.h>

// Local
#include "Context.hpp"

namespace kadm5
{

using boost::shared_ptr;
using std::string;
using std::vector;

class Principal;

/**
 * \brief
 * Represents a Connection to a KAdmin server.
 * 
 * Connection and Principal provide the the complete interface to manipulate
 * the Kerberos database. Only rare cases should require to use other
 * classes as well.
 * 
 * Use the factory functions <code>from_*</code> to create Connection
 * instances. These instances should be used to create Principal objects which
 * represent entries in the Kerberos database. See Principal documentation for
 * a small example.
 * 
 * \author Peter Dinges <me@elwedgo.de>
 **/
class Connection
{
public:
	///@{\name Factory Functions
	
	/**
	 * Factory function to create a Connection authenticating via the
	 * given password.
	 * 
	 * \param	password	The password to use for authentication.
	 * \param	client	The name of the Kerberos principal to 
	 * 			authenticate as. If missing, the libraries'
	 * 			default value will be used.
	 * \param	realm	The name of the realm to assume if this part
	 * 			of a Principal's name is omitted. If missing,
	 * 			the libraries' default value will be used.
	 * \param	host	Hostname of the KAdmin server to connect to.
	 * 			If missing, the <code>admin_server</code>
	 * 			parameter from the Kerberos configuration will
	 * 			be used.
	 * \param	port	The port number used by the KAdmin server.
	 * \return	a smart pointer to the the freshly created and
	 * 		initialized Connection.
	 **/
	static shared_ptr<Connection> from_password(
		const string& password,
		const string& client ="",
		const string& realm ="",
		const string& host ="",
		const int port =0
	);
// TODO Implement
//	static shared_ptr<Connection> from_keytab();

	/**
	 * Factory function to create a Connection using authentication
	 * information from the given credential cache.
	 * 
	 * \param	ccname	Use credentials from this cache. The name may
	 * 			be a filename or any other valid identifier
	 * 			of form <code>TYPE:ID</code> understood by the
	 * 			libraries. If <code>TYPE:</code> is omitted,
	 * 			<code>FILE:</code> is assumed.
	 * \param	realm	The name of the realm to assume if this part
	 * 			of a Principal's name is omitted. If missing,
	 * 			the libraries' default value will be used.
	 * \param	host	Hostname of the KAdmin server to connect to.
	 * 			If missing, the <code>admin_server</code>
	 * 			parameter from the Kerberos configuration will
	 * 			be used.
	 * \param	port	The port number used by the KAdmin server.
	 * \return	a smart pointer to the the freshly created and
	 * 		initialized Connection.
	 **/
	static shared_ptr<Connection> from_credential_cache(
		const string& ccname = "",
		const string& realm ="",
		const string& host ="",
		const int port =0
	);
	///@}

	/**
	 * Create a new Principal with the given name in memory.
	 * 
	 * This function may throw exceptions if the Principal already exists.
	 * 
	 * \note
	 * The creation remains unnoticed by the server until
	 * Principal::commit_modifications() is executed.
	 * 
	 * \todo	Make list of thrown exceptions (on minor errors)
	 * 		explicit.
	 * 
	 * \param	name	The name of the new Principal. If the realm
	 * 			part is omitted, the Connection defaults
	 * 			(see realm()) will be used.
	 * \param	password	The new Principal's password. If empty,
	 * 			a completely random key will be used. (See
	 * 			Principal::randomize_keys().)
	 * \return	a smart pointer to a freshly created Principal not yet
	 * 		existing in the Kerberos database.
	 **/
	shared_ptr<Principal> create_principal(
		const string& name,
		const string& password =""
	) const;
	
	/**
	 * Delete the Principal with the given id from the Kerberos database.
	 * 
	 * \note This function affects the database instantly.
	 * 
	 * \param	id	The id (name) of the Kerberos Principal to
	 * 			delete. If the realm part is omitted, the
	 * 			Connection defaults (see realm()) will be used.
	 **/
	void delete_principal(const string& id) const;
	
	/**
	 * Fetch a Kerberos Principal from the database.
	 * 
	 * \note
	 * Modifications remain unnoticed by the server until
	 * Principal::commit_modifications() is executed.
	 * 
	 * \param	id	The id (name) of the Kerberos Principal to
	 * 			fetch. If the realm part is omitted, the
	 * 			Connection defaults (see realm()) will be used.
	 * \return	a smart pointer to the fetched Principal.
	 **/
	shared_ptr<Principal> get_principal(const string& id) const;
	
	/**
	 * Fetch a list of Kerberos Principals whose names match the given
	 * search string.
	 * 
	 * \note
	 * Modifications to the Principals remain unnoticed by the server until
	 * Principal::commit_modifications() is executed.
	 * 
	 * \param	filter	The search string to match the Principal names
	 * 			against.
	 * \return	a list of Principals whose names match the filter.
	 **/
	shared_ptr< vector< shared_ptr<Principal> > > get_principals(
		const string& filter
	) const;
	
	/**
	 * Fetch a list of <em>names</em> of Kerberos Principals matching the
	 * given search string.
	 * 
	 * \param	filter	The search string to match the Principal names
	 * 			against.
	 * \return	a list of Principal names that match the filter.
	 **/
	shared_ptr< vector<string> > list_principals(
		const string& filter
	) const;


	 ///@{\name Privilege Tests
	 /**
	 * Test if detailed Principal data may be fetched from the KAdmin
	 * server. This is needed to add and modify Principals.
	 * 
	 * \note
	 * This function checks if the <code>KADM5_PRIV_GET</code> privilege
	 * flag is set.
	 * 
	 * \return	true, if Principal detail data may be fetched.
	 **/
	const bool may_get() const { return has_privilege(KADM5_PRIV_GET); }
	
	/**
	 * Test if new Principals may be added to the Kerberos database.
	 * 
	 * \note
	 * This function checks if the <code>KADM5_PRIV_ADD</code> privilege
	 * flag is set.
	 * 
	 * \return	true, if new Principals may be added.
	 **/
	const bool may_add() const { return has_privilege(KADM5_PRIV_ADD); }

	/**
	 * Test if existing Principals may be modified.
	 * 
	 * \note
	 * This function checks if the <code>KADM5_PRIV_MODIFY</code> privilege
	 * flag is set.
	 * 
	 * \return	true, if existing Principals may be modified.
	 **/
	const bool may_modify() const { return has_privilege(KADM5_PRIV_MODIFY); }

	/**
	 * Test if existing Principals may be deleted.
	 * 
	 * \note
	 * This function checks if the <code>KADM5_PRIV_DELETE</code> privilege
	 * flag is set.
	 * 
	 * \return	true, if existing Principals may be deleted.
	 **/
	const bool may_delete() const { return has_privilege(KADM5_PRIV_DELETE); }

	/**
	 * Test if a list of Principal names may be retrieved from server.
	 * 
	 * \note
	 * This function checks if the <code>KADM5_PRIV_LIST</code> privilege
	 * flag is set.
	 * 
	 * \return	true, if Principal names may be listed.
	 **/
	const bool may_list() const { return has_privilege(KADM5_PRIV_LIST); }

	/**
	 * Test if foreign Principal passwords may be changed.
	 * 
	 * \note
	 * This function checks if the <code>KADM5_PRIV_CPW</code> privilege
	 * flag is set.
	 * 
	 * \return	true, if foreign Principal passwords may be changed.
	 **/
	const bool may_change_password() const { return has_privilege(KADM5_PRIV_CPW); }

	/**
	 * Convenience function to test, if this Connection possesses all
	 * available privileges.
	 * 
	 * \return	true, if this Connection has all privileges.
	 **/
	const bool may_all() const { return has_privilege(KADM5_PRIV_ALL); }
	///@}
	
	
	///@{\name Connection Information
	/**
	 * Get the Principal name used to connect to the KAdmin server.
	 * 
	 * \return	the Principal name used to connect to the KAdmin
	 * 		server.
	 **/
	const string client() const { return _context->client(); }

	/**
	 * Get the realm used as default (if realm part of Principal name from
	 * this Connection is omitted).
	 * 
	 * \return	the default realm for this Connection to a KAdmin
	 * 		server.
	 **/
	const string realm() const { return _context->realm(); }
	
	/**
	 * Get the hostname of the KAdmin server used.
	 * 
	 * \return	the hostname of the KAdmin server used.
	 **/
	const string host() const { return _context->host(); }

	/**
	 * Get the port number the KAdmin server uses.
	 * 
	 * \return	the port number the KAdmin server uses.
	 **/
	const int port() const { return _context->port(); }
	///@}
	
private:
	/**
	 * Constructor called by factory functions after creating a suitable
	 * Context object.
	 * 
	 * \param	context	Connect using this Context.
	 */
	explicit Connection(shared_ptr<Context> context);
	
	/**
	 * Helper function to test if current connection is privileged for
	 * all actions indicated by <code>flags</code>.
	 * 
	 * \param	flags	Bit-Flags representing the privileges to test
	 * 			for. see <code>kadm5/admin.h</code> for
	 * 			<code>#DEFINE</code>s.
	 * \return	true, if current connection holds all privileges
	 * 		indicated by <code>flags</code>.
	 **/
	const bool has_privilege(u_int32_t flags) const;

	/** Kerberos and KAdmin context for this Connection. */
	shared_ptr<Context> _context;
};

} /* namespace kadm5 */

#endif /*CONNECTION_HPP_*/
