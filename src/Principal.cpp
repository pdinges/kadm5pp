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
#include <boost/bind.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>

// Kerberos
#include <heimdal/kadm5/admin.h>

// Local
#include "Principal.hpp"
#include "Error.hpp"

namespace kadm5
{

using std::auto_ptr;


Principal::Principal(
	shared_ptr<Context> context,
	const string& id,
	const string& password
) :
	_context(context),
	_id( parse_name(_context, id) ),
	_data(),
	_password(NULL),
	_loaded(false),
	_exists(false),
	_modified_mask(0)
{
	KADM5_DEBUG("Principal::Principal(): Constructing...\n");
	_data.reset(
		new kadm5_principal_ent_rec,
		boost::bind(delete_kadm5_principal_ent, _context, _1)
	);
	memset(_data.get(), 0, sizeof(kadm5_principal_ent_rec));
	_data->principal = _id.get();
	
	if (password.length() > 0) {
		set_password(password);
	}
}


Principal::~Principal()
{
	// Prevent double-deletion if both point to the same data.
	if (_data->principal == _id.get()) {
		_data->principal = NULL;
	}
	wipe(_password);
	KADM5_DEBUG("Principal::~Principal(): Destroyed.\n");
}


string Principal::id() const
{
	return unparse_name(_context, _id.get());
}


bool Principal::exists_on_server() const
{
	load();
	return _exists;
}


bool Principal::modified() const
{
	return	!exists_on_server() ||
		(_modified_mask != 0) ||
		(_password != NULL);
}


void Principal::commit_modifications()
{
	if (!exists_on_server()) {
		apply_create();
	}
	
	if (_password) {
		apply_password();
	}
	
	if (_modified_mask & KADM5_PRINCIPAL) {
		apply_rename();
	}
	
	if (_modified_mask & (~KADM5_PRINCIPAL)) {
		apply_modify();
	}
}


string Principal::name() const
{
	return unparse_name(_context, _data->principal);
}


void Principal::set_name(const string& name)
{
	// Provide best exception safety here
	krb5_principal pnew = NULL;
	Error::throw_on_error( krb5_parse_name(*_context, name.c_str(), &pnew) );
	
	krb5_principal ptmp = _data->principal;
	_data->principal = pnew;
	_modified_mask |= KADM5_PRINCIPAL;

	if (ptmp != _id.get()) {
		delete_krb5_principal(_context, ptmp);
	}
}


void Principal::set_password(const string& password)
{
	auto_ptr<char> tmp(new char[password.length() + 1]);
	password.copy(tmp.get(), string::npos);
	tmp.get()[password.length()] = 0;

	char* old = _password;
	_password = tmp.release();
	
	wipe(old);
}


//void Principal::randomizePassword(const PasswordGenerator& pwGen)
//{
//	string pw = pwGen.randomPassword();
//	int n = pw.size();
//
//	wipePassword();
//	_password = new char[n+1];
//
//	strncpy(_password, pw.c_str(), n);
//	_password[n] = 0;
//}


ptime Principal::expire_time() const
{
	load();
	if (_data->princ_expire_time > 0) {
		return boost::posix_time::from_time_t(_data->princ_expire_time);
	}
	else {
		return boost::posix_time::pos_infin;
	}
}


void Principal::set_expire_time(const ptime& t)
{
	krb5_timestamp old = _data->princ_expire_time;
	
	if (t.is_infinity() || t < ptime(boost::gregorian::date(1970,1,1))) {
		_data->princ_expire_time = 0;
	}
	else {
		ptime epoch(boost::gregorian::date(1970,1,1));
		time_duration d = t - epoch;
		_data->princ_expire_time = d.total_seconds();
	}
	
	if (old != _data->princ_expire_time) {
		_modified_mask |= KADM5_PRINC_EXPIRE_TIME;
	}
}


ptime Principal::last_password_change() const
{
	load();
	if (_data->last_pwd_change > 0) {
		return boost::posix_time::from_time_t(_data->last_pwd_change);
	}
	else {
		return boost::posix_time::neg_infin;
	}
}


ptime Principal::password_expiration() const
{
	load();
	if (_data->pw_expiration > 0) {
		return boost::posix_time::from_time_t(_data->pw_expiration);
	}
	else {
		return boost::posix_time::pos_infin;
	}
}


void Principal::set_password_expiration(const ptime& t)
{
	krb5_timestamp old = _data->pw_expiration;
	
	if (t.is_infinity() || t < ptime(boost::gregorian::date(1970,1,1))) {
		_data->pw_expiration = 0;
	}
	else {
		ptime epoch(boost::gregorian::date(1970,1,1));
		time_duration d = t - epoch;
		_data->pw_expiration = d.total_seconds();
	}
	
	if (old != _data->pw_expiration) {
		_modified_mask |= KADM5_PW_EXPIRATION;
	}
}


time_duration Principal::max_lifetime() const
{
	load();
	if (_data->max_life > 0) {
		return boost::posix_time::seconds(_data->max_life);
	}
	else {
		return boost::posix_time::pos_infin;
	}
}


void Principal::set_max_lifetime(const time_duration& d)
{
	krb5_timestamp old = _data->max_life;
	
	if (d.is_pos_infinity() || d < boost::posix_time::seconds(1)) {
		_data->max_life = 0;
	}
	else {
		_data->max_life = d.total_seconds();
	}
	
	if (old != _data->max_life) {
		_modified_mask |= KADM5_MAX_LIFE;
	}
}


time_duration Principal::max_renewable_lifetime() const
{
	load();
	if (_data->max_renewable_life > 0) {
		return boost::posix_time::seconds(_data->max_renewable_life);
	}
	else {
		return boost::posix_time::pos_infin;
	}
}


void Principal::set_max_renewable_lifetime(const time_duration& d)
{
	krb5_deltat old = _data->max_renewable_life;
	
	if (d.is_pos_infinity() || d < boost::posix_time::seconds(1)) {
		_data->max_renewable_life = 0;
	}
	else {
		_data->max_renewable_life = d.total_seconds();
	}
	
	if (old != _data->max_renewable_life) {
		_modified_mask |= KADM5_MAX_RLIFE;
	}
}


//Principal* Principal::getModifier() const
//{
//	char* name = NULL;
//	Principal* ret = NULL;
//	
//	if (existsOnServer()) {
//		_context->unparseName(_data->mod_name, &name);
//		ret = new Principal(_context, name);
//		delete name;
//		
//		return ret;
//	} else {
//		return NULL;
//	}
//}


ptime Principal::modify_time() const
{
	load();
	if (_data->mod_date > 0) {
		return boost::posix_time::from_time_t(_data->mod_date);
	}
	else {
		return boost::posix_time::neg_infin;
	}
}


ptime Principal::last_success() const
{
	load();
	if (_data->last_success > 0) {
		return boost::posix_time::from_time_t(_data->last_success);
	}
	else {
		return boost::posix_time::neg_infin;
	}
}


ptime Principal::last_failed() const
{
	load();
	if (_data->last_failed > 0) {
		return boost::posix_time::from_time_t(_data->last_failed);
	}
	else {
		return boost::posix_time::neg_infin;
	}
}


void Principal::load() const
{
	if (_loaded) {
		return;
	}

	// Load everything except the modified entries.
	// Exception: We _must_ load the principal entry so back it up
	// and restore afterwards.
	krb5_principal ptmp = NULL;
	krb5_principal pbackup = _data->principal;
	_data->principal = NULL;

	try {
		Error::throw_on_error(
			kadm5_get_principal(
				*_context,
				_id.get(),
				_data.get(),
				(~_modified_mask) | KADM5_PRINCIPAL
			)
		);
		KADM5_DEBUG("Principal::load(): Fetched data from server.\n");

		_exists = true;
	}
	catch (UnknownPrincipalError) {
		KADM5_DEBUG("Principal::load(): Fetching default values.\n");

		// Load defaults then (== get default principal)
		// pbackup always points to the right krb5_principal, even
		// if name and realm were changed.
		shared_ptr<krb5_realm> prealm( krb5_princ_realm(*_context, pbackup) );

		Error::throw_on_error(
			krb5_make_principal(*_context, &ptmp, *prealm, "default", NULL)
		);
		shared_ptr<krb5_principal_data> pdefault(
			ptmp, boost::bind(delete_krb5_principal, _context, _1)
		);
		
		Error::throw_on_error(
			kadm5_get_principal(
				*_context,
				pdefault.get(),
				_data.get(),
				(~_modified_mask) | KADM5_PRINCIPAL
			)
		);
	}
	
	ptmp = _data->principal;
	_data->principal = pbackup;
	_loaded = true;
	
	delete_krb5_principal(_context, ptmp);
}



void Principal::apply_create()
{
	KADM5_DEBUG("Principal::apply_create()\n");
	if (!_password) {
//		randomize_password();
	}
	
	Error::throw_on_error(
		kadm5_create_principal(
			*_context,
			_data.get(),
			(_modified_mask | KADM5_PRINCIPAL) & (~forbidden_create_flags),
			_password
		)
	);
	
	// _id and _data->principal might point to the same object but reset()
	// handles this, so nothing is destroyed accidentaly.
	_id.reset(
		_data->principal, boost::bind(delete_krb5_principal, _context, _1)
	);
	
	_modified_mask = 0;
	_exists = true;
	// As we don't know the default values for omitted fields.
	_loaded = false;
	
	wipe(_password);
}


void Principal::apply_rename()
{
	KADM5_DEBUG("Principal::apply_rename()\n");
	Error::throw_on_error(
		kadm5_rename_principal(
			*_context,
			_id.get(),
			_data->principal
		)
	);
	
	_modified_mask &= ~KADM5_PRINCIPAL;
	// _id and _data->principal might point to the same object but reset()
	// handles this, so nothing is destroyed accidentaly.
	_id.reset(
		_data->principal, boost::bind(delete_krb5_principal, _context, _1)
	);
}


void Principal::apply_modify() const
{
	KADM5_DEBUG("Principal::apply_modify()\n");

	// Use id known by the server
	krb5_principal ptmp = _data->principal;
	_data->principal = _id.get();
	
	Error::throw_on_error(
		kadm5_modify_principal(
			*_context,
			_data.get(),
			_modified_mask & (~forbidden_modify_flags)
		)
	);
	
	_data->principal = ptmp;
	_modified_mask &= forbidden_modify_flags;
}


void Principal::apply_password() const
{
	if (_password) {
		KADM5_DEBUG("Principal::apply_password(): Changing password.\n");
		Error::throw_on_error(
			kadm5_chpass_principal(*_context, _id.get(), _password)
		);
		
		// Wipe password immediately from memory.
		wipe(_password);
	}
}


void Principal::wipe(char*& cstr) const
{
	if (cstr) {
		KADM5_DEBUG("Principal::wipe(): Wiping password from memory.\n");
		memset(cstr, 0, strlen(cstr));
		delete[] cstr;
		cstr = NULL;
	}
}

}
