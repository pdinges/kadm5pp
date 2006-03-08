#ifndef CONTEXT_HPP_
#define CONTEXT_HPP_

#include <krb5.h>
#include <heimdal/kadm5/admin.h>

#include "Error.hpp"

namespace KAdm5
{

class Context
{
public:
	~Context();

	/* KAdmin library functions */
	void chpassPrincipal(krb5_principal, char*) const;
	void chpassPrincipal(krb5_principal, int, krb5_key_data*) const;
	
	void createPrincipal(kadm5_principal_ent_t, u_int32_t, char*) const;
	void deletePrincipal(krb5_principal) const;
	
	void flush() const;
	
	void freeKeyData(int16_t*, krb5_key_data*) const;
	void freeNameList(char**, int*) const;
	void freePrincipalEnt(kadm5_principal_ent_t) const;
	
	void getPrincipal(krb5_principal, kadm5_principal_ent_t, u_int32_t) const;
	void getPrincipals(const char*, char***, int*) const;
	void getPrivs(u_int32_t*) const;
	
	void modifyPrincipal(kadm5_principal_ent_t, u_int32_t) const;
	void randkeyPrincipal(krb5_principal, krb5_keyblock**, int*) const;
	void renamePrincipal(krb5_principal, krb5_principal) const;

	/* Kerberos library functions */
	void parseName(const char*, krb5_principal*) const;
	void unparseName(krb5_const_principal, char**) const;
	krb5_realm* princRealm(krb5_principal) const;
	void makePrincipal(krb5_principal*, krb5_const_realm, const char*) const;
	
	void freePrincipal(krb5_principal) const;

protected:
	Context(const char* =NULL, const char* =NULL, const int =0);
	
	kadm5_config_params* _config_params;
	krb5_context _krb_context;
	void* _kadm_handle;
};

}

#endif /*CONTEXT_HPP_*/
