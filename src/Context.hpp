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

#ifndef CONTEXT_HPP_
#define CONTEXT_HPP_

// STL and Boost
#include <string>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>

// Kerberos
#include <krb5.h>
#include <kadm5/admin.h>

namespace kadm5
{

using boost::shared_ptr;
using std::string;

/**
 * \brief
 * Abstract RAII base class for holding pointers to Kerberos and KAdmin
 * context information. Resource pointers will be initialized and deleted
 * automatically.
 * 
 * For convenience, this class provides implicit conversion functions to
 * (pointers to) the context structures <code>krb5_context</code> and
 * <code>void*</code>. Therefore, instances may be used as drop-in
 * replacements to the context pointers required by the library functions.
 * 
 * Concrete implementations, e.g. a PasswordContext may be used as follows:
 * \code
 * PasswordContext pc(...);
 * u_int32_t privs;
 * 
 * // Use instance pc instead of KAdmin server handle (of type void*).
 * kadm5_get_privs(pc, &privs);
 * \endcode
 * 
 * KAdmin connection parameters (<code>kadm5_config_params</code>) are
 * generated automatically.
 * 
 * \note
 * This class is <code>noncopyable</code> as it holds resource pointers.
 * 
 * Classes derived from this class must set the Context::_kadm_handle in their
 * constructors via Context::set_kadm_handle().
 * 
 * \author Peter Dinges <me@elwedgo.de>
 **/
class Context : public boost::noncopyable
{
public:
	// Implicit type conversion for library functions
	operator krb5_context_data*() const { return _krb_context.get(); }
	operator void*() const { return _kadm_handle.get(); }
	
	/**
	 * Get the name of the Kerberos principal this context uses for
	 * connection to the KAdmin server.
	 * 
	 * \return The Kerberos principal used to connect to the KAdmin server.
	 **/
	const string client() const;
	
	/**
	 * Get the realm name this context uses.
	 * 
	 * \return The Kerberos realm of this context.
	 **/
	const string realm() const;
	
	/**
	 * Get the used KAdmin server's hostname.
	 * 
	 * \return The hostname of this context's KAdmin server.
	 **/
	const string host() const;
	
	/**
	 * Get the used KAdmin server's port number.
	 * 
	 * \return The port number of this context's KAdmin server.
	 **/
	const int port() const;

protected:
	/**
	 * Create a Context with the given connection data.
	 * 
	 * \note
	 * If <code>host</code> contains a port number (i.e., is of form
	 * <code>hostname:port</code>), that port will overwrite the method's
	 * <code>port</code> parameter.
	 * 
	 * \param	client	The principal used for identification to the
	 * 			KAdmin server. If empty, defaults to the
	 * 			Kerberos libraries' default value.
	 * \param	realm	The Kerberos realm for this context (will be
	 * 			used as default for all principals without
	 * 			explicitly specified realm).
	 * 			If empty, the default realm will be used.
	 * \param	host	The hostname of the KAdmin server' to which to
	 *			connect. If emmpty, defaults to the used realm's
	 * 			<code>admin_server</code> config parameter.
	 * \param	port	The KAdmin server's port number.
	 * 			If <code>0</code>, uses the libraries' default
	 * 			port number.
	 **/
	explicit Context(
		const string& client,
		const string& realm,
		const string& host,
		const int port
	);

	/**
	 * Set the _kadm_handle data member. This method must be called
	 * in constructors of directly derived classes.
	 * 
	 * \param	ph	Smart pointer to the KAdmin connection handle.
	 **/
	void set_kadm_handle(shared_ptr<void> ph) { _kadm_handle = ph; }
	
	/**
	 * Helper function to retrieve the <code>kadm5_config_params</code>
	 * in constructors of derived classes.
	 * 
	 * \return	a smart pointer to the <code>kadm5_config_params</code>
	 * 		for this Context.
	 **/
	shared_ptr<kadm5_config_params> config_params() { return _config_params; }

private:
	/** Kerberos context information. */
	shared_ptr<krb5_context_data> _krb_context;
	/** KAdmin connection configuration parameters. */
	shared_ptr<kadm5_config_params> _config_params;
	/** Client name (as it isn't saved in Context::_config_params). */
	string _client;
	/** KAdmin connection handle. */
	shared_ptr<void> _kadm_handle;
};


/* Helper functions for structure memory management with shared_ptr<T>. */

/**
 * Factory function to create and initialize
 * <code>kadm5_config_params</code> to be used in KAdmin connection
 * initialization.
 * 
 * \param	realm	The Kerberos realm.
 * \param	host	The KAdmin server's hostname (or IP).
 * \param	port	The KAdmin server's port number.
 * \return	a smart pointer to an initialized
 * 		<code>kadm5_config_params</code> structure on the heap.
 **/
shared_ptr<kadm5_config_params> create_config_params(
	const string& realm,
	const string& host,
	const int port
);

/**
 * Custom deletion function to dispose <code>kadm5_config_params</code>
 * structures. This is a helper function to be used with
 * <code>boost::shared_ptr<kadm5_config_params></code>.
 * 
 * \param	pp	Pointer to the <code>kadm5_config_params</code>
 * 			structure to delete.
 **/
void delete_config_params(kadm5_config_params* pp);

/**
 * Custom deletion function to dispose <code>krb5_principal</code>s when
 * deleting a <code>boost::shared_ptr<krb5_prinicpal_data></code>.
 * 
 * The Context pointer is necessary because the Kerberos libraries require it
 * for deletion. Use <code>boost::bind</code> to derive a unary function
 * for the <code>boost::shared_ptr</code> constructor:
 * \code
 * Context pc;
 * boost::shared_ptr<kadm5_principal_ent_rec> pp(
 * 	new kadm5_principal_ent_rec,
 * 	boost::bind(delete_kadm5_principal_ent, pc, _1)
 * );
 * \endcode
 * 
 * \param	pc	Smart pointer to the Context in which the
 * 			<code>krb5_principal</code> was registered/created.
 * \param	pp	The <code>krb5_principal</code> to delete.
 **/
void delete_krb5_principal(shared_ptr<const Context> pc, krb5_principal pp);

/**
 * Creates a deep copy of the given <code>kadm5_principal_ent_t</code>.
 * 
 * \todo	Also copy tl_data and key_data fields.
 * 
 * \param	pc	Smart pointer to the Context in which the
 * 			<code>kadm5_principal_ent_t</code> should be created.
 * \param	pp	The <code>kadm5_principal_ent_t</code> to copy.
 * \return	A smart pointer to the deep copy.
 **/
shared_ptr<kadm5_principal_ent_rec> copy_kadm5_principal_ent(
	shared_ptr<const Context> pc,
	const kadm5_principal_ent_t pp
);

/**
 * Custom deletion function to dispose <code>kadm5_principal_ent_t</code>s on
 * when deleting a <code>boost::shared_ptr<kadm5_principal_ent_rec></code>.
 * 
 * See kadm5::delete_krb5_principal() for an example.
 * 
 * \param	pc	Smart pointer to the Context in which the
 * 			<code>kadm5_principal_ent_t</code> was created.
 * \param	pp	The <code>kadm5_principal_ent_t</code> to delete.
 **/
void delete_kadm5_principal_ent(
	shared_ptr<const Context> pc,
	kadm5_principal_ent_t pp
);


/* Convenience wrappers for library functions */

/**
 * Convenience wrapper for the <code>krb5_parse_name</code> Kerberos library
 * function. It returns an initialized smart pointer to a fresh
 * <code>krb5_principal</code> structure with the given name.
 * 
 * This function may throw exceptions; however, it guarantees that no memory
 * leaks will result from such a case.
 * 
 * \param	pc	The Context in which to create the
 * 			<code>krb5_principal</code>.
 * \param	name	The principal's name.
 * \return	a pointer to the freshly allocated and initialized
 * 		<code>krb5_principal</code>.
 **/
shared_ptr<krb5_principal_data> parse_name(
	shared_ptr<const Context> pc,
	const string& name
);

/**
 * Convenience wrapper for the <code>krb5_unparse_name</code> Kerberos library
 * function. It returns a string holding the given
 * <code>krb5_principal</code>'s name.
 * 
 * This function may throw exceptions but guarantees that no memory leaks will
 * result from such a case.
 * 
 * \param	pc	The Context to which the <code>krb5_principal</code>
 *			belongs.
 * \param	pp	A pointer to the <code>krb5_principal</code> whose name
 * 			should be retrieved.
 * \return	the principal's name.
 **/
string unparse_name(
	shared_ptr<const Context> pc,
	krb5_const_principal pp
);

} /* namespace kadm5 */

#endif /*CONTEXT_HPP_*/
