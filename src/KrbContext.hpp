#ifndef KRBCONTEXT_HPP_
#define KRBCONTEXT_HPP_

#include <string>
using std::string;

#include <krb5.h>
#include <heimdal/kadm5/admin.h>

#include "AdmContext.hpp"

namespace KAdm5
{

/**
 * \brief Wrapper class for Kerberos 5 library functions which require a context
 *        object.
 */
class KrbContext
{
public:
	KrbContext();
	~KrbContext();

	AdmContext* createAdmContext(const char* =NULL, const char* =NULL, const int =0);
	
	void parseName(const char*, krb5_principal*) const;
	void unparseName(krb5_const_principal, char**) const;
	krb5_realm* princRealm(krb5_principal) const;
	void makePrincipal(krb5_principal*, krb5_const_realm, const char*) const;
	
	void freePrincipal(krb5_principal) const;
	
private:
	krb5_context _context;
};

}

#endif /*KRBCONTEXT_HPP_*/
