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

#ifndef PRINCIPAL_H_
#define PRINCIPAL_H_

// STL and Boost
#include <string>
#include <boost/date_time/posix_time/posix_time.hpp>

// Local
//#include "PasswordGenerator.hpp"
#include "Connection.hpp"

namespace kadm5
{
	
using boost::posix_time::ptime;
using boost::posix_time::time_duration;
using boost::shared_ptr;
using std::string;

class Context;

/**
 * \brief
 * Represents a Principal in the Kerberos database.
 * 
 * This class should be your main interface to modify the Kerberos database.
 * Together with the Connection class, all operations that can be performed
 * through the <code>kadmin</code> commandline program may also be achieved
 * using these classes. Single exception is the (local) database dump.
 * 
 * To reduce network load, data will be fetched from the server only if needed.
 * 
 * Any changes made will be invisible to the server until
 * commit_modifications() is executed.
 * 
 * Passwords will be wiped from memory after successful transmission to the
 * server.
 * 
 * Small usage example:
 * \code
 * boost::smart_ptr<Connection> pc( Connection::from_password("adminpw") );
 * boost::smart_ptr<Principal> pp( pc->get_principal("foo") );
 * 
 * pp->set_name("bar");		// rename foo -> bar
 * pp->set_password("secret");	// change password
 * pp->commit_modifications();	// make changes visible
 * \endcode
 * 
 * \author Peter Dinges <me@elwedgo.de>
 **/
class Principal
{
public:
	///@{\name Constructors and Destructors
	/**
	 * Constructs a new Principal belonging to the given Context.
	 * 
	 * \note
	 * This constructor is not intended for direct use. Instead, new
	 * Principal instances should be created by the
	 * Connection::create_principal(), Connection::get_principal() and
	 * Connection::get_principals() factory functions.
	 * 
	 * \todo
	 * Maybe make this constructor private and a friend of Connection to
	 * prevent its usage?
	 * 
	 * \param	context	The Context the new Principal belongs to.
	 * \param	id	The unique name, this Principal is known as in
	 * 			the Kerberos database. If the realm part is
	 * 			omitted, Context::realm() will be used.
	 * \param	password	The password for Principals not yet
	 * 			existing in the Kerberos database. If empty,
	 * 			a random key will be used for this Principal
	 * 			(see randomize_keys()).
	 * 
	 * 			If set for a Principal that exists_on_server(),
	 * 			the value will be treated as changed password.
	 **/
	explicit Principal(
		shared_ptr<Context> context,
		const string& id,
		const string& password=""
	);
	
	/**
	 * Cleans up on destruction (surprise! :-)).
	 **/
	virtual ~Principal();
	///@}

	///@{\name Kerberos Database Functions
	/**
	 * Check if this Principal exists in the Kerberos database (and hence
	 * was loaded from there) or if it was created from scratch.
	 * 
	 * \return	true, if this Principal represents an existing entry in
	 * 		the Kerberos database.
	 **/
	const bool exists_on_server() const;
	
	/**
	 * Test whether this Principal's data differs from the values saved in
	 * the Kerberos database.
	 * 
	 * \return	True, if attributes were modified after they were
	 * 		fetched from the server or if this is a new Principal.
	 * 		False otherwise.
	 **/
	const bool modified() const;
	
	/**
	 * Commit all changes to the database.
	 **/
	void commit_modifications();
	///@}

	
	/**
	 * Get the name, this Principal is currently known as to the server
	 * (if it exists_on_server()).
	 * 
	 * \return	The Principal's unique name in the Kerberos Database.
	 **/
	const string id() const;
	
	/**
	 * Get the Principal's name.
	 * 
	 * \note
	 * This may differ from id() as it can be changed with set_name().
	 * commit_modifications() triggers a rename and hence afterwards,
	 * there's always <code>id() == name()</code>.
	 * 
	 * \return	The Principal's name.
	 **/
	const string name() const;
	
	/**
	 * Set the Principal's name.
	 * 
	 * \see name() for more information on how this relates to id().
	 * 
	 * \param	name	The Principal's new name.
	 **/
	void set_name(const string& name);
	
	/**
	 * Set the Principal's password.
	 * 
	 * \note
	 * On commit_modifications(), the password will be wiped from memory.
	 * 
	 * \param	password	The new password.
	 **/
	void set_password(const string& password);
// TODO Implement.
//	void randomize_password(const PasswordGenerator& =KAdm5::PasswordGenerator());
//	void randomize_keys();
	
	/**
	 * Get the expiration date. After this date, the Principal will be
	 * unable to authenticate (e.g. log in).
	 * 
	 * \return	The expiration date. This may be
	 * 		<code>boost::posix_time::pos_infin</code> if the
	 * 		Principal never expires.
	 **/
	const ptime expire_time() const;
	
	/**
	 * Set the expiration date.
	 * 
	 * \param	t	The new date on which the Principal will
	 * 			expire.	Use
	 * 			<code>boost::posix_time::pos_infin</code> to
	 * 			have the Principal never expire.
	 **/
	void set_expire_time(const ptime& t);
	
	/**
	 * Get the password expiration date. After this date, the Principal
	 * will be forced to change his password.
	 * 
	 * \return	The password expiration date. This may be
	 * 		<code>boost::posix_time::pos_infin</code> if the
	 * 		password never expires.
	 **/
	const ptime password_expiration() const;
	
	/**
	 * Set the password expiration date.
	 * 
	 * \param	t	The new date on which the password will expire.
	 * 			Use <code>boost::posix_time::pos_infin</code>
	 * 			to have the password never expire.
	 **/
	void set_password_expiration(const ptime& t);
	
	/**
	 * Get the Principal's maximum Kerberos ticket lifetime.
	 * 
	 * \return	The maximum ticket lifetime. This may be
	 * 		<code>boost::posix_time::pos_infin</code> if the
	 * 		ticket supports unlimited lifetime.
	 * 		(Be careful with such tickets! They are a major
	 * 		security risk.)
	 **/
	const time_duration max_lifetime() const;
	
	/**
	 * Set the Principal's maximum Kerberos ticket lifetime.
	 * 
	 * \param	d	The new maximum ticket lifetime.
	 * 			Use <code>boost::posix_time::pos_infin</code>
	 * 			to support never expiring tickets. (Again, be
	 * 			careful with such tickets!)
	 **/
	void set_max_lifetime(const time_duration& d);

	/**
	 * Get the maximum lifetime in which the Principal may renew held
	 * tickets.
	 * 
	 * \return	The maximum time for ticket renewal. This may be
	 * 		<code>boost::posix_time::pos_infin</code> if the
	 * 		ticket supports unlimited lifetime.
	 * 		(Be careful with such tickets! They are a major
	 * 		security risk.)
	 **/
	const time_duration max_renewable_lifetime() const;
	
	/**
	 * Set the new lifetime in which the Principal may renew held tickets.
	 * 
	 * \param	d	The new maximum ticket renewing lifetime.
	 * 			Use <code>boost::posix_time::pos_infin</code>
	 * 			to support never expiring tickets. (Again, be
	 * 			careful with such tickets!)
	 **/
	void set_max_renewable_lifetime(const time_duration& d);

//	u_int32_t key_version() const;
//	void set_key_version(u_int32_t v);

//	const Policy* getPolicy() const;
//	void setPolicy(Policy*);

//	Principal modifier() const;

	/**
	 * Get the latest date on which the Principal's database entry was
	 * modified.
	 * 
	 * \return	The latest date, on which the Principal's database
	 * 		entry was modified. This may be 
	 * 		<code>boost::posix_time::neg_infin</code> if it has
	 * 		never been modified.
	 **/
	const ptime modify_time() const;
	
	/**
	 * Get the latest date on which the Principal's password was changed
	 * in the database.
	 * 
	 * \note
	 * This will return meaningful values only if the KAdmin server
	 * supports writing back this information into the database.
	 * (Compile-time setting.)
	 * 
	 * \todo
	 * Check if this <em>really</em> depends on a compile-time setting.
	 * 
	 * \return	The latest date, on which the Principal's password
	 * 		was changed in the database. This may be 
	 * 		<code>boost::posix_time::neg_infin</code> if it has
	 * 		never been changed or if the server does not support
	 * 		this information.
	 **/
	const ptime last_password_change() const;

	/**
	 * Get the latest date on which the Principal successfully
	 * authenticated to the KDC.
	 * 
	 * \note
	 * This will return meaningful values only if the KDC server
	 * supports writing back this information into the database.
	 * (Compile-time setting.)
	 * 
	 * \return	The latest date, on which the Principal successfully
	 * 		authenticated to the KDC. This may be 
	 * 		<code>boost::posix_time::neg_infin</code> if that has
	 * 		never been the case or if the server does not support
	 * 		this information.
	 **/
	const ptime last_success() const;

	/**
	 * Get the latest date on which the Principal failed to authenticate
	 * to the KDC.
	 * 
	 * \note
	 * This will return meaningful values only if the KDC server
	 * supports writing back this information into the database.
	 * (Compile-time setting.)
	 * 
	 * \return	The latest date, on which the Principal failed to
	 * 		authenticate to the KDC. This may be 
	 * 		<code>boost::posix_time::neg_infin</code> if that has
	 * 		never been the case or if the server does not support
	 * 		this information.
	 **/
	const ptime last_failed() const;
	
// TODO Implement accessors for the following kadm5_principal_ent_t members:
//    krb5_flags attributes;
//    u_int32_t aux_attributes;
//
//    krb5_kvno mkvno;
//
//    krb5_kvno fail_auth_count;
	
private:
	// delete_principal() is part of Connection's interface for a more
	// consistent interface. It still needs to access _id though.
	friend void Connection::delete_principal(const string& id) const;
	
	/**
	 * Fetch the Principal's entry (identified by id()) from the Kerberos
	 * database if it exists or use default values otherwise.
	 * 
	 * load() will check if it has been called before and do nothing in
	 * that case. Also, it won't overwrite already changed attributes.
	 **/
	void load() const;
	
	/**
	 * Helper function to add a (this) new Principal entry to the Kerberos
	 * database.
	 **/
	void apply_create();
	
	/**
	 * Helper function to perform a rename of this Principal (from id() to
	 * name()).
	 **/
	void apply_rename();
	
	/**
	 * Helper function to perform the actual modifications of the
	 * (already existing!) Principal's database entry.
	 **/
	void apply_modify() const;
	
	/**
	 * Helper function to change the Principal's password in the database.
	 **/
	void apply_password() const;
	
	/**
	 * Helper function to wipe the contents of the given string from
	 * memory. The string will be set to all <code>0</code>s first and
	 * then be deallocated.
	 * 
	 * It is save to call this function with <code>NULL</code>.
	 * 
	 * \param	cstr	The string to wipe from memory.
	 * 			<code>NULL</code> pointers will be ignored.
	 **/
	void wipe(char*& cstr) const;

	
	/* Data members */
	
	/** The Context this Principal belongs to. */
	shared_ptr<Context> _context;
	/**
	 * The krb5_principal under which this Principal is known to the
	 * KAdmin server.
	 **/
	shared_ptr<krb5_principal_data> _id;
	/** The structure holding all attribute data. See <kadm5/admin.h> */
	shared_ptr<kadm5_principal_ent_rec> _data; 
	/** The Principal's password-to-be. */
	mutable char* _password;	// Use char* instead of string so we
					// may be sure to wipe the contents
					// from memory.
	/** Flag to check if the data was loaded before. */
	mutable bool _loaded;
	/** Flag to check if the Principal has an entry on the server. */
	mutable bool _exists;
	/** Bit-mask to remember which attributes were changed. */
	mutable u_int32_t _modified_mask;

	// See MIT Kerberos 5 kadm API documentation for a list of forbidden
	// flags in the different operations.
	static const u_int32_t forbidden_create_flags =
		( KADM5_LAST_PWD_CHANGE | KADM5_MOD_TIME | KADM5_MOD_NAME \
		| KADM5_MKVNO | KADM5_AUX_ATTRIBUTES | KADM5_POLICY_CLR \
		| KADM5_LAST_SUCCESS | KADM5_LAST_FAILED \
		| KADM5_FAIL_AUTH_COUNT | KADM5_KEY_DATA );
	static const u_int32_t forbidden_modify_flags = 
		( KADM5_PRINCIPAL | KADM5_LAST_PWD_CHANGE | KADM5_MOD_TIME \
		| KADM5_MOD_NAME | KADM5_MKVNO | KADM5_AUX_ATTRIBUTES \
		| KADM5_LAST_SUCCESS | KADM5_LAST_FAILED | KADM5_KEY_DATA );
};

} /* namespace kadm5 */

#endif /*PRINCIPAL_H_*/
