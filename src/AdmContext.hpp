#ifndef ADMCONTEXT_HPP_
#define ADMCONTEXT_HPP_

#include <krb5.h>
#include <heimdal/kadm5/admin.h>

#include "Error.hpp"

namespace KAdm5
{

class AdmContext
{
public:
	AdmContext(krb5_context, const char* =NULL, const char* =NULL, const int =0);
	~AdmContext();

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
	
private:
	kadm5_config_params* _config_params;
	void* _kadm_handle;
};

}

#endif /*ADMCONTEXT_HPP_*/
