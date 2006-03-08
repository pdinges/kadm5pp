#include "Principal.hpp"

#include <memory>
#include <boost/date_time/gregorian/gregorian.hpp>

#include <heimdal/kadm5/admin.h>

namespace KAdm5
{
using std::auto_ptr;


Principal::Principal(const string& name, Context* context) :
	_context(context),
	_data(NULL),
	_id(NULL),
	_loaded(false),
	_exists(false),
	_modifiedMask(0)
{

	_data = new kadm5_principal_ent_rec;
	memset(_data, 0, sizeof(kadm5_principal_ent_rec));
	
	// TODO Use makePrincipal here
	context->parseName(name.c_str(), &_id);
}


Principal::~Principal()
{
	if (_data) {
		if (_data->principal) {
			_context->freePrincipal(_data->principal);
		}
		// FIXME Causes double free error?
//		_context->freePrincipalEnt(_data);
	}
}


string Principal::getId()
{
	char* id = NULL;

	_context->unparseName(_id, &id);
	string ret(id);
	delete id;

	return ret;
}


bool Principal::existsOnServer() throw(Error)
{
	load();
	return _exists;
}


bool Principal::wasModified()
{
	return _modifiedMask != 0;
}


void Principal::commitChanges() throw(Error)
{
	if (!existsOnServer()) {
		applyCreate();
		_modifiedMask = 0;
		return;
	}

	if (!_modifiedMask) {
		return;
	}
	load();

	if (_modifiedMask & KADM5_PRINCIPAL) {
		applyRename();
	}
}


string Principal::getName()
{
	char* name = NULL;
	
	if (_data->principal) {
		try {
			_context->unparseName(_data->principal, &name);
			string ret(name);
			delete name;
			
			return ret;
		}
		catch(UnknownPrincipalError& e) {
			delete name;
		}
	}

	return getId();
}


void Principal::setName(const string& name)
{
	krb5_principal p = NULL;
	
	if (_data->principal) {
		_context->freePrincipal(_data->principal);
	}
	
	// TODO Maybe use makePrincipal?
	_context->parseName(name.c_str(), &p);
	_data->principal = p;
	_modifiedMask |= KADM5_PRINCIPAL;
}


void Principal::setPassword(const string& password)
{
}


boost::posix_time::ptime Principal::getExpireTime()
{
	load();
	return boost::posix_time::from_time_t(_data->princ_expire_time);
}


void Principal::setExpireTime(const boost::posix_time::ptime& t)
{
	boost::posix_time::ptime epoch(boost::gregorian::date(1970,1,1));
	boost::posix_time::time_duration d = t - epoch;

	_data->princ_expire_time = d.total_seconds();
	_modifiedMask |= KADM5_PRINC_EXPIRE_TIME;
}


boost::posix_time::ptime Principal::getLastPasswordChange()
{
	load();
	return boost::posix_time::from_time_t(_data->last_pwd_change);
}


boost::posix_time::ptime Principal::getPasswordExpiration()
{
	load();
	return boost::posix_time::from_time_t(_data->pw_expiration);
}


Principal* Principal::getModifier()
{
	char* name = NULL;
	Principal* ret = NULL;
	
	if (existsOnServer()) {
		_context->unparseName(_data->mod_name, &name);
		ret = new Principal(name, _context);
		delete name;
		
		return ret;
	} else {
		return NULL;
	}
}


boost::posix_time::ptime Principal::getModifyTime()
{
	load();
	return boost::posix_time::from_time_t(_data->mod_date);
}


boost::posix_time::ptime Principal::getLastSuccess()
{
	load();
	return boost::posix_time::from_time_t(_data->last_success);
}


boost::posix_time::ptime Principal::getLastFailed()
{
	load();
	return boost::posix_time::from_time_t(_data->last_failed);
}


void Principal::applyCreate()
{
	bool nameLoaded = (_data->principal != NULL);
	if (!nameLoaded) {
		_data->principal = _id;
	}

	// TODO Use flags and password!
	_context->createPrincipal(
		_data,
//		KADM5_ATTRIBUTES | KADM5_MAX_LIFE | KADM5_MAX_RLIFE |
//		KADM5_PRINC_EXPIRE_TIME | KADM5_PW_EXPIRATION | KADM5_PRINCIPAL,
		KADM5_PRINCIPAL,
		""
	);
	
	if (!nameLoaded) {
		_data->principal = NULL;
	}
}


void Principal::applyRename()
{
	_context->renamePrincipal(_id, _data->principal);
	// Copy id first so an exception in freePrincipal() won't
	// render the object unusable.
	krb5_principal p = _id;
	_context->parseName(getName().c_str(), &_id);
	_context->freePrincipal(p);
	_modifiedMask &= ~KADM5_PRINCIPAL;
}


void Principal::load()
{
	if (_loaded || _exists) {
		return;
	}

	// Load everything except the modified entries.
	// Exception: We _must_ load the principal entry so back it up
	// and restore afterwards.
	krb5_principal p = _data->principal;
	_data->principal = NULL;

	try {
		_context->getPrincipal(
			_id, _data, ~_modifiedMask | KADM5_PRINCIPAL);

		_exists = true;
	}
	catch (UnknownPrincipalError) {
		// Load defaults then (== get default principal)
		krb5_principal defaultPrincipal = NULL;
		// FIXME Realm may have changed from principal's id.
		krb5_realm* realm = _context->princRealm(_id);
		_context->makePrincipal(&defaultPrincipal, *realm, "default");
		
		_context->getPrincipal(
			defaultPrincipal, _data, ~_modifiedMask | KADM5_PRINCIPAL);
		
		_context->freePrincipal(defaultPrincipal);
	}

	_context->freePrincipal(_data->principal);
	_data->principal = p;

	_loaded = true;
}

}
