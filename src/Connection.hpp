#ifndef CONTEXT_HPP_
#define CONTEXT_HPP_

#include <string>
#include <vector>

#include <krb5.h>
#include <heimdal/kadm5/admin.h>

#include "Error.hpp"
#include "KrbContext.hpp"
#include "AdmContext.hpp"
#include "Principal.hpp"

namespace KAdm5
{
using std::string;
using std::vector;

class Connection
{
public:
	Connection(const string& ="", const string& ="", const int =0);
	~Connection();
	
	Principal* createPrincipal(const string&) const;
//	void deletePrincipal(const string&);
	void deletePrincipal(Principal*) const;

	Principal* getPrincipal(const string&) const;
	std::vector<Principal*>* getPrincipals(const string&) const;
	std::vector<string>* listPrincipals(const string&) const;


	bool mayGet() const { return hasPrivilege(KADM5_PRIV_GET); }
	bool mayAdd() const { return hasPrivilege(KADM5_PRIV_ADD); }
	bool mayModify() const { return hasPrivilege(KADM5_PRIV_MODIFY); }
	bool mayDelete() const { return hasPrivilege(KADM5_PRIV_DELETE); }
	bool mayList() const { return hasPrivilege(KADM5_PRIV_LIST); }
	bool mayChangePassword() const { return hasPrivilege(KADM5_PRIV_CPW); }
	bool mayAll() const { return hasPrivilege(KADM5_PRIV_ALL); }
	
private:
	bool hasPrivilege(u_int32_t) const;

	KrbContext* _krbContext;
	AdmContext* _admContext;
};

}
#endif /*CONTEXT_HPP_*/
