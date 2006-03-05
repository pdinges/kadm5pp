#include "AdmContext.hpp"

#include <cstring>

namespace KAdm5
{

AdmContext::AdmContext(krb5_context context, const char* realm, const char* host, const int port)
	:	_config_params(NULL),
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
		
		
		// Create server handle.		
		// TODO Use credentials cache
		Error::checkReturnVal(
			kadm5_init_with_creds_ctx(
				context,
				NULL,
				NULL,
				KADM5_ADMIN_SERVICE,
				_config_params,
				0,
				0,
				&_kadm_handle
			)
//			kadm5_init_with_password_ctx(
//				context,
//				NULL,
//				NULL,
//				KADM5_ADMIN_SERVICE,
//				_config_params,
//				0,
//				0,
//				&_kadm_handle
//			)
		);
	}
	catch (...) {
		// In case of an emergency, use destructor to clean up.
		this->~AdmContext();
		throw;
	}
}


AdmContext::~AdmContext()
{
	// Unconditional delete works because all values are NULL initialized.
	delete _config_params->realm;
	delete _config_params->admin_server;
	delete _config_params;
	
	if (_kadm_handle) {
		kadm5_destroy(_kadm_handle);
	}
}


void AdmContext::chpassPrincipal(krb5_principal principal, char* password) const
{
	Error::checkReturnVal(
		kadm5_chpass_principal(
			_kadm_handle,
			principal,
			password
		)
	);
}


void AdmContext::chpassPrincipal(krb5_principal principal, int keyCount, krb5_key_data* keyData) const
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


void AdmContext::createPrincipal(kadm5_principal_ent_t principal, u_int32_t mask, char* password) const
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


void AdmContext::deletePrincipal(krb5_principal principal) const
{
	Error::checkReturnVal(
		kadm5_delete_principal(_kadm_handle, principal)
	);
}


void AdmContext::flush() const
{
	Error::checkReturnVal(
		kadm5_flush(_kadm_handle)
	);
}

void AdmContext::freeKeyData(int16_t* keyCount, krb5_key_data* keyData) const
{
	kadm5_free_key_data(_kadm_handle, keyCount, keyData);
}


void AdmContext::freeNameList(char** list, int* count) const
{
	kadm5_free_name_list(_kadm_handle, list, count);
}


void AdmContext::freePrincipalEnt(kadm5_principal_ent_t principal) const
{
	kadm5_free_principal_ent(_kadm_handle, principal);
}


void AdmContext::getPrincipal(krb5_principal principal, kadm5_principal_ent_t output, u_int32_t mask) const
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


void AdmContext::getPrincipals(const char* filter, char*** nameList, int* nameCount) const
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


void AdmContext::getPrivs(u_int32_t* privileges) const
{
	Error::checkReturnVal(
		kadm5_get_privs(_kadm_handle, privileges)
	);
}

void AdmContext::modifyPrincipal(kadm5_principal_ent_t principal, u_int32_t mask) const
{
	Error::checkReturnVal(
		kadm5_modify_principal(_kadm_handle, principal, mask)
	);
}


void AdmContext::randkeyPrincipal(krb5_principal principal, krb5_keyblock** newKeyData, int* keyCount) const
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


void AdmContext::renamePrincipal(krb5_principal source, krb5_principal target) const
{
	Error::checkReturnVal(
		kadm5_rename_principal(_kadm_handle, source, target)
	);
}


}
