#include "KrbContext.hpp"

namespace KAdm5
{

KrbContext::KrbContext()
	: _context(NULL)
{
	Error::checkReturnVal(
		krb5_init_context(&_context)
	);
}


KrbContext::~KrbContext()
{
	krb5_free_context(_context);
}


AdmContext* KrbContext::createAdmContext(const char* realm, const char* host, const int port)
{
	return new AdmContext(_context, realm, host, port);
}


void KrbContext::parseName(const char* name, krb5_principal* principal) const
{
	Error::checkReturnVal(
		krb5_parse_name(_context, name, principal)
	);
}


void KrbContext::unparseName(krb5_const_principal principal, char** name) const
{
	Error::checkReturnVal(
		krb5_unparse_name(_context, principal, name)
	);
}


krb5_realm* KrbContext::princRealm(krb5_principal principal) const
{
	return krb5_princ_realm(_context, principal);
}

// TODO Make argument list variable to match library declaration.
void KrbContext::makePrincipal(krb5_principal* principal, krb5_const_realm realm, const char* name) const
{
	Error::checkReturnVal(
		krb5_make_principal(_context, principal, realm, name, NULL)
	);
}


void KrbContext::freePrincipal(krb5_principal principal) const
{
	krb5_free_principal(_context, principal);
}


}
