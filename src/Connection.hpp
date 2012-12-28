/******************************************************************************
 *                                                                            *
 *  Copyright (c) 2006 Peter Dinges <pdinges@acm.org>                           *
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


#ifndef CONNECTION_HPP_
#define CONNECTION_HPP_

// STL and Boost
#include <string>
#include <vector>
#include <boost/shared_ptr.hpp>

// Kerberos
#include <krb5.h>
#include <kadm5/admin.h>

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
 * Connection and Principal provide the complete interface to manipulate
 * the Kerberos database. Only rare cases should require using other
 * classes.
 * 
 * Use one of the factory functions <code>from_*</code> to create a Connection
 * instance. Then, employ this instance to retrieve Principal objects, which
 * represent entries in the Kerberos database. See the Principal documentation
 * for a small example.
 * 
 * \author Peter Dinges <pdinges@acm.org>
 **/
class Connection
{
public:
	///@{\name Factory Functions
	
	/**
	 * Factory function that creates a Connection, authenticating via the
	 * given password.
	 * 
	 * \param	password	The password used for authentication.
	 * \param	client	The name of the Kerberos principal to
	 * 			authenticate as. If missing, the libraries'
	 * 			default value will be used.
	 * \param	realm	The realm to assume if this part of a
	 * 			Principal's name is omitted. If missing,
	 * 			the libraries' default value will be used.
	 * \param	host	Hostname of the KAdmin server to connect to.
	 * 			If missing, defaults to the
	 * 			<code>admin_server</code> parameter in the
	 * 			Kerberos configuration.
	 * \param	port	The KAdmin server's port number.
	 * \return	a smart pointer to the created and initialized
	 * 		Connection.
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
	 * Factory function that creates a Connection from authentication
	 * information in a credential cache.
	 * 
	 * \param	ccname	Use credentials from this cache. The name may
	 * 			be a filename or any other valid identifier
	 * 			of form <code>TYPE:ID</code> that the libraries
	 * 			understand. If <code>TYPE:</code> is omitted,
	 * 			<code>FILE:</code> is assumed.
	 * \param	realm	The Kerberos realm for this context. It will be
	 * 			used as default for all principals without
	 * 			specified realm.
	 * 			If missing, the default realm will be used.
	 * \param	host	Hostname of the KAdmin server to which to
	 *			connect.
	 * 			If empty, defaults to the used realm's
	 * 			<code>admin_server</code> config parameter.
	 * \param	port	The KAdmin server's port number.
	 * \return	a smart pointer to the freshly created and
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
	 * Principal::commit_modifications() is called.
	 * 
	 * \todo	Make list of thrown exceptions (on minor errors)
	 * 		explicit.
	 * 
	 * \param	name	The name of the new Principal. If the realm
	 * 			part is omitted, the Connection default
	 * 			(see realm()) will be used.
	 * \param	password	The new Principal's password. If empty,
	 * 			defaults to a completely random key. (See
	 * 			Principal::randomize_keys().)
	 * \return	a smart pointer to a new Principal instance that does
	 * 		not yet exist in the Kerberos database.
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
	 * 			Connection default (see realm()) will be used.
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
	 * 			Connection default (see realm()) will be used.
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
	 * \param	filter	The search string against which the Principal
	 * 			names are matched.
	 * \return	a list containing all Principals whose names match the
	 *		filter.
	 **/
	shared_ptr< vector< shared_ptr<Principal> > > get_principals(
		const string& filter
	) const;
	
	/**
	 * Fetch a list of <em>names</em> of Kerberos Principals matching the
	 * given search string.
	 * 
	 * \param	filter	The search string against which the Principal
	 * 			names are matched.
	 * \return	a list containing all Principal names that match the
	 *		filter.
	 **/
	shared_ptr< vector<string> > list_principals(
		const string& filter
	) const;


	 ///@{\name Privilege Tests
	 /**
	 * Test whether detailed Principal data may be retrieved from the KAdmin
	 * server. This is required for adding and modifying Principals.
	 * 
	 * \note
	 * This method checks whether the <code>KADM5_PRIV_GET</code> privilege
	 * flag is set.
	 * 
	 * \return	true if Principal details may be retrieved.
	 **/
	const bool may_get() const { return has_privilege(KADM5_PRIV_GET); }
	
	/**
	 * Test whether new Principals may be added to the Kerberos database.
	 * 
	 * \note
	 * This method checks whether the <code>KADM5_PRIV_ADD</code> privilege
	 * flag is set.
	 * 
	 * \return	true if new Principals may be added.
	 **/
	const bool may_add() const { return has_privilege(KADM5_PRIV_ADD); }

	/**
	 * Test whether existing Principals may be modified.
	 * 
	 * \note
	 * This method checks whether the <code>KADM5_PRIV_MODIFY</code>
	 * privilege flag is set.
	 * 
	 * \return	true if existing Principals may be modified.
	 **/
	const bool may_modify() const { return has_privilege(KADM5_PRIV_MODIFY); }

	/**
	 * Test whether existing Principals may be deleted.
	 * 
	 * \note
	 * This method checks whether the <code>KADM5_PRIV_DELETE</code>
	 * privilege flag is set.
	 * 
	 * \return	true if existing Principals may be deleted.
	 **/
	const bool may_delete() const { return has_privilege(KADM5_PRIV_DELETE); }

	/**
	 * Test whether a list of Principal names may be retrieved from the
	 * server.
	 * 
	 * \note
	 * This method checks whether the <code>KADM5_PRIV_LIST</code> privilege
	 * flag is set.
	 * 
	 * \return	true if Principal names may be listed.
	 **/
	const bool may_list() const { return has_privilege(KADM5_PRIV_LIST); }

	/**
	 * Test whether other Principals' passwords may be changed.
	 * 
	 * \note
	 * This method checks whether the <code>KADM5_PRIV_CPW</code> privilege
	 * flag is set.
	 * 
	 * \return	true if other Principals' passwords may be changed.
	 **/
	const bool may_change_password() const { return has_privilege(KADM5_PRIV_CPW); }

	/**
	 * Convenience method to test whether this Connection is granted all
	 * available privileges.
	 * 
	 * \return	true if this Connection has all privileges.
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
	 * Get the default realm (that is used when the realm part of a
	 * Principal from this Connection is omitted).
	 * 
	 * \return	the default realm for this Connection.
	 **/
	const string realm() const { return _context->realm(); }
	
	/**
	 * Get the used KAdmin server's hostname.
	 * 
	 * \return	the KAdmin server's hostname.
	 **/
	const string host() const { return _context->host(); }

	/**
	 * Get the KAdmin server's port number.
	 * 
	 * \return	the KAdmin server's port number.
	 **/
	const int port() const { return _context->port(); }
	///@}
	
private:
	/**
	 * Constructor called by the factory functions after creating a suitable
	 * Context object.
	 * 
	 * \param	context	Connect using this Context.
	 */
	explicit Connection(shared_ptr<Context> context);
	
	/**
	 * Helper function to test whether current connection is privileged for
	 * the actions indicated by <code>flags</code>.
	 * 
	 * \param	flags	Bit-Flags representing the privileges to test
	 * 			for. See <code>kadm5/admin.h</code> for
	 * 			<code>#DEFINE</code>s.
	 * \return	true if the current connection holds all privileges
	 * 		indicated by <code>flags</code>.
	 **/
	const bool has_privilege(u_int32_t flags) const;

	/** Kerberos and KAdmin context for this Connection. */
	shared_ptr<Context> _context;
};

} /* namespace kadm5 */

#endif /*CONNECTION_HPP_*/
