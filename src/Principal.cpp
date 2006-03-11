#include "Principal.hpp"

#include <memory>
#include <boost/date_time/gregorian/gregorian.hpp>

#include <heimdal/kadm5/admin.h>

#define KADM5_FORBIDDEN_CREATE_MASK \
	( KADM5_LAST_PWD_CHANGE | KADM5_MOD_TIME | KADM5_MOD_NAME \
	| KADM5_MKVNO | KADM5_AUX_ATTRIBUTES | KADM5_POLICY_CLR \
	| KADM5_LAST_SUCCESS | KADM5_LAST_FAILED | KADM5_FAIL_AUTH_COUNT \
	| KADM5_KEY_DATA )
#define KADM5_FORBIDDEN_MODIFY_MASK \
	( KADM5_PRINCIPAL | KADM5_LAST_PWD_CHANGE | KADM5_MOD_TIME \
	| KADM5_MOD_NAME | KADM5_MKVNO | KADM5_AUX_ATTRIBUTES \
	| KADM5_LAST_SUCCESS | KADM5_LAST_FAILED | KADM5_KEY_DATA )


namespace KAdm5
{
using std::auto_ptr;


Principal::Principal(Context* context, const string& name, const string& password) :
	_context(context),
	_data(NULL),
	_id(NULL),
	_password(NULL),
	_loaded(false),
	_exists(false),
	_modifiedMask(0)
{

	_data = new kadm5_principal_ent_rec;
	memset(_data, 0, sizeof(kadm5_principal_ent_rec));
	
	context->parseName(name.c_str(), &_id);

	if (password.size() > 0) {
		setPassword(password.c_str());
	}
}


Principal::~Principal()
{
	if (_data) {
		if (_id) {
			_context->freePrincipal(_id);
		}
		_context->freePrincipalEnt(_data);
	}
	wipePassword();
}


string Principal::getId() const
{
	char* id = NULL;

	_context->unparseName(_id, &id);
	string ret(id);
	delete id;

	return ret;
}


bool Principal::existsOnServer() const
{
	load();
	return _exists;
}


bool Principal::wasModified() const
{
	return (_modifiedMask != 0) || (_password != NULL);
}


void Principal::commitChanges()
{
	if (!existsOnServer()) {
		applyCreate();
		_modifiedMask = 0;
		return;
	}

	if (_password) {
		applyPwChange();
	}
	
	if (!wasModified()) {
		return;
	}
	load();

	if (_modifiedMask & KADM5_PRINCIPAL) {
		applyRename();
	}
	
	if (_modifiedMask) {
		applyModify();
	}
}


string Principal::getName() const
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
	
	_context->parseName(name.c_str(), &p);
	_data->principal = p;
	_modifiedMask |= KADM5_PRINCIPAL;
}


void Principal::setPassword(const string& password)
{
	wipePassword();
	
	int n = password.size() + 1;
	_password = new char[n];
	strncpy(_password, password.c_str(), n);
}


void Principal::randomizePassword(const PasswordGenerator& pwGen)
{
	string pw = pwGen.randomPassword();
	int n = pw.size();

	wipePassword();
	_password = new char[n+1];

	strncpy(_password, pw.c_str(), n);
	_password[n] = 0;
}


ptime Principal::getExpireTime() const
{
	load();
	if (_data->princ_expire_time > 0) {
		return boost::posix_time::from_time_t(_data->princ_expire_time);
	}
	else {
		return boost::posix_time::pos_infin;
	}
}


void Principal::setExpireTime(const ptime& t)
{
	if (t.is_infinity() || t < ptime(boost::gregorian::date(1970,1,1))) {
		_data->princ_expire_time = 0;
	}
	else {
		ptime epoch(boost::gregorian::date(1970,1,1));
		time_duration d = t - epoch;
		_data->princ_expire_time = d.total_seconds();
	}
	
	_modifiedMask |= KADM5_PRINC_EXPIRE_TIME;
}


ptime Principal::getLastPasswordChange() const
{
	load();
	if (_data->last_pwd_change > 0) {
		return boost::posix_time::from_time_t(_data->last_pwd_change);
	}
	else {
		return boost::posix_time::neg_infin;
	}
}


ptime Principal::getPasswordExpiration() const
{
	load();
	if (_data->pw_expiration > 0) {
		return boost::posix_time::from_time_t(_data->pw_expiration);
	}
	else {
		return boost::posix_time::pos_infin;
	}
}


void Principal::setPasswordExpiration(const ptime& t)
{
	if (t.is_infinity() || t < ptime(boost::gregorian::date(1970,1,1))) {
		_data->pw_expiration = 0;
	}
	else {
		ptime epoch(boost::gregorian::date(1970,1,1));
		time_duration d = t - epoch;
		_data->pw_expiration = d.total_seconds();
	}
	
	_modifiedMask |= KADM5_PW_EXPIRATION;
}


time_duration Principal::getMaxLifetime() const
{
	load();
	if (_data->max_life > 0) {
		return boost::posix_time::seconds(_data->max_life);
	}
	else {
		return boost::posix_time::pos_infin;
	}
}


void Principal::setMaxLifetime(const time_duration& d)
{
	if (d.is_pos_infinity() || d < boost::posix_time::seconds(1)) {
		_data->max_life = 0;
	}
	else {
		_data->max_life = d.total_seconds();
	}
	
	_modifiedMask |= KADM5_MAX_LIFE;
}


time_duration Principal::getMaxRenewableLifetime() const
{
	load();
	if (_data->max_renewable_life > 0) {
		return boost::posix_time::seconds(_data->max_renewable_life);
	}
	else {
		return boost::posix_time::pos_infin;
	}
}


void Principal::setMaxRenewableLifetime(const time_duration& d)
{
	if (d.is_pos_infinity() || d < boost::posix_time::seconds(1)) {
		_data->max_renewable_life = 0;
	}
	else {
		_data->max_renewable_life = d.total_seconds();
	}
	
	_modifiedMask |= KADM5_MAX_RLIFE;
}


Principal* Principal::getModifier() const
{
	char* name = NULL;
	Principal* ret = NULL;
	
	if (existsOnServer()) {
		_context->unparseName(_data->mod_name, &name);
		ret = new Principal(_context, name);
		delete name;
		
		return ret;
	} else {
		return NULL;
	}
}


ptime Principal::getModifyTime() const
{
	load();
	if (_data->mod_date > 0) {
		return boost::posix_time::from_time_t(_data->mod_date);
	}
	else {
		return boost::posix_time::neg_infin;
	}
}


ptime Principal::getLastSuccess() const
{
	load();
	if (_data->last_success > 0) {
		return boost::posix_time::from_time_t(_data->last_success);
	}
	else {
		return boost::posix_time::neg_infin;
	}
}


ptime Principal::getLastFailed() const
{
	load();
	if (_data->last_failed > 0) {
		return boost::posix_time::from_time_t(_data->last_failed);
	}
	else {
		return boost::posix_time::neg_infin;
	}
}


void Principal::applyCreate()
{
	bool nameLoaded = (_data->principal != NULL);
	if (!nameLoaded) {
		_data->principal = _id;
	}
	
	if (!_password) {
		randomizePassword();
	}

	_context->createPrincipal(
		_data,
		(_modifiedMask | KADM5_PRINCIPAL) & ~KADM5_FORBIDDEN_CREATE_MASK,
		_password
	);

	wipePassword();

	_modifiedMask = 0;
	_exists = true;
	
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


void Principal::applyModify() const
{
	bool nameLoaded = (_data->principal != NULL);
	if (!nameLoaded) {
		_data->principal = _id;
	}
	
	_context->modifyPrincipal(
		_data,
		_modifiedMask & ~(KADM5_FORBIDDEN_MODIFY_MASK)
	);

	if (!nameLoaded) {
		_data->principal = NULL;
	}
	_modifiedMask = 0;	// FIXME Is this always legal?
}


void Principal::applyPwChange() const
{
	_context->chpassPrincipal(_id, _password);
	
	// Wipe password immediately from memory.
	wipePassword();
}


void Principal::load() const
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


void Principal::wipePassword() const
{
	if (_password) {
		memset(_password, 0, strlen(_password));
		delete[] _password;
	}
}

}
