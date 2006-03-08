#include "Context.hpp"

#include <cstring>

namespace KAdm5
{

Context::Context(const char* client, const char* realm, const char* host, const int port)
	:	_config_params(NULL),
		_client(NULL),
		_krb_context(NULL),
		_kadm_handle(NULL)
{
	int n = 0;
	
	// Structure 0-setting is important for the destructor.
	// (Unused pointers must be NULL.)
	kadm5_config_params* c = new kadm5_config_params;
	memset(c, 0, sizeof(kadm5_config_params));
	
	// Auto-Pointers are not feasible here so do resource
	// management by hand.
	try {
		// Save config parameters.
		if (client) {
			n = strlen(client) + 1;
			_client = new char[n];
			strncpy(_client, client, n);
		}
		
		if (realm) {
			n = strlen(realm) + 1;
			c->realm = new char[n];
			strncpy(c->realm, realm, n);
	
			c->mask |= KADM5_CONFIG_REALM;
		}		
	
		if (host) {
			n = strlen(host) + 1;
			c->admin_server = new char[n];
			strncpy(c->admin_server, host, n);
	
			c->mask |= KADM5_CONFIG_ADMIN_SERVER;
		}		
		
		if (port > 0) {
			c->kadmind_port = port;
			c->mask |= KADM5_CONFIG_KADMIND_PORT;
		}
	
		_config_params = c;
		
		Error::checkReturnVal(
			krb5_init_context(&_krb_context)
		);
		if (c->realm) {
			krb5_set_default_realm(_krb_context, c->realm);
		}
		
	}
	catch (...) {
		// In case of an emergency, use destructor to clean up.
		this->~Context();
		throw;
	}
}


Context::~Context()
{
	if (_kadm_handle) {
		kadm5_destroy(_kadm_handle);
	}

	if (_krb_context) {
		krb5_free_context(_krb_context);
	}
	
	// Unconditional delete works because all values are NULL initialized.
	delete _client;
	delete[] _config_params->realm;
	delete[] _config_params->admin_server;
	delete _config_params;
}


const char* Context::client() const
{
	// TODO Return default if not set.
	return _client;
}


const char* Context::realm() const
{
	// TODO Return default if not set.
	return _config_params->realm;
}


const char* Context::host() const
{
	// TODO Return default if not set.
	return _config_params->admin_server;
}


int Context::port() const
{
	// TODO Return default if not set.
	return _config_params->kadmind_port;
}


void Context::chpassPrincipal(krb5_principal principal, char* password) const
{
	Error::checkReturnVal(
		kadm5_chpass_principal(
			_kadm_handle,
			principal,
			password
		)
	);
}


void Context::chpassPrincipal(krb5_principal principal, int keyCount, krb5_key_data* keyData) const
{
	Error::checkReturnVal(
		kadm5_chpass_principal_with_key(
			_kadm_handle,
			principal,
			keyCount,
			keyData
		)
	);
}


void Context::createPrincipal(kadm5_principal_ent_t principal, u_int32_t mask, char* password) const
{
	Error::checkReturnVal(
		kadm5_create_principal(
			_kadm_handle,
			principal,
			mask,
			password
		)
	);
}


void Context::deletePrincipal(krb5_principal principal) const
{
	Error::checkReturnVal(
		kadm5_delete_principal(_kadm_handle, principal)
	);
}


void Context::freeKeyData(int16_t* keyCount, krb5_key_data* keyData) const
{
	kadm5_free_key_data(_kadm_handle, keyCount, keyData);
}


void Context::freeNameList(char** list, int* count) const
{
	kadm5_free_name_list(_kadm_handle, list, count);
}


void Context::freePrincipalEnt(kadm5_principal_ent_t principal) const
{
	kadm5_free_principal_ent(_kadm_handle, principal);
}


void Context::getPrincipal(krb5_principal principal, kadm5_principal_ent_t output, u_int32_t mask) const
{
	Error::checkReturnVal(
		kadm5_get_principal(
			_kadm_handle,
			principal,
			output,
			mask
		)
	);
}


void Context::getPrincipals(const char* filter, char*** nameList, int* nameCount) const
{
	Error::checkReturnVal(
		kadm5_get_principals(
			_kadm_handle,
			filter,
			nameList,
			nameCount
		)
	);
}


void Context::getPrivs(u_int32_t* privileges) const
{
	Error::checkReturnVal(
		kadm5_get_privs(_kadm_handle, privileges)
	);
}

void Context::modifyPrincipal(kadm5_principal_ent_t principal, u_int32_t mask) const
{
	Error::checkReturnVal(
		kadm5_modify_principal(_kadm_handle, principal, mask)
	);
}


void Context::randkeyPrincipal(krb5_principal principal, krb5_keyblock** newKeyData, int* keyCount) const
{
	Error::checkReturnVal(
		kadm5_randkey_principal(
			_kadm_handle,
			principal,
			newKeyData,
			keyCount
		)
	);
}


void Context::renamePrincipal(krb5_principal source, krb5_principal target) const
{
	Error::checkReturnVal(
		kadm5_rename_principal(_kadm_handle, source, target)
	);
}


void Context::parseName(const char* name, krb5_principal* principal) const
{
	Error::checkReturnVal(
		krb5_parse_name(_krb_context, name, principal)
	);
}


void Context::unparseName(krb5_const_principal principal, char** name) const
{
	Error::checkReturnVal(
		krb5_unparse_name(_krb_context, principal, name)
	);
}


krb5_realm* Context::princRealm(krb5_principal principal) const
{
	return krb5_princ_realm(_krb_context, principal);
}

// TODO Make argument list variable to match library declaration.
void Context::makePrincipal(krb5_principal* principal, krb5_const_realm realm, const char* name) const
{
	Error::checkReturnVal(
		krb5_make_principal(_krb_context, principal, realm, name, NULL)
	);
}


void Context::freePrincipal(krb5_principal principal) const
{
	krb5_free_principal(_krb_context, principal);
}


}
