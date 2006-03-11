#include "Connection.hpp"
#include "PasswordContext.hpp"

namespace KAdm5
{


Connection* Connection::fromPassword(
	const string& password,
	const string& client,
	const string& realm,
	const string& host,
	const int port
) {
	const char* c = client.empty() ? NULL : client.c_str();
	const char* r = realm.empty() ? NULL : realm.c_str();
	const char* h = host.empty() ? NULL : host.c_str();
	
	auto_ptr<Context> ctx(
		new PasswordContext(password.c_str(), c, r, h, port)
	);

	return new Connection(ctx);
}


Connection::Connection(auto_ptr<Context> context)
	:	_context(context)
{
}


Principal* Connection::createPrincipal(const string& name, const string& password) const
{
	if (!mayAdd()) {
		throw AddAuthError(KADM5_AUTH_ADD);
	}
	
	Principal* p = new Principal(_context.get(), name, password);
	
	auto_ptr< vector<string> > existing( listPrincipals(p->getId()) );
	
	// A bad principal name will throw an exception in listPrincipals(),
	// so this test will work correctly.
	if (existing->size() != 0) {
		delete p;
		throw AlreadyExists(0);
	}
	
	return p;
}


void Connection::deletePrincipal(Principal* principal) const
{
	krb5_principal id = NULL;
	_context->parseName(principal->getId().c_str(), &id);
	
	// TODO Make this prettier. Maybe construct auto_ptr like
	// class and modify library functions to support it.
	try {
		_context->deletePrincipal(id);
	}
	catch(...) {
		_context->freePrincipal(id);
		throw;
	}
	_context->freePrincipal(id);
}


void Connection::deletePrincipal(const string& id) const
{
	auto_ptr<Principal> p( getPrincipal(id) );
	deletePrincipal(p.get());
}


Principal* Connection::getPrincipal(const string& name) const
{
	if (!mayGet()) {
		throw GetAuthError(KADM5_AUTH_GET);
	}
	
	auto_ptr< vector<string> > candidates( listPrincipals(name) );
	
	// Unambiguous description suffices.
	if (candidates->size() == 1) {
		return new Principal(_context.get(), (*candidates)[0]);
	} else if (candidates->size() < 1) {
		throw UnknownPrincipalError(KADM5_UNK_PRINC);
	} else {
		throw AmbiguousKeyError(KADM5_AMBIGUOUS_KEY);
	}
}


std::vector<Principal*>* Connection::getPrincipals(const string& filter) const
{
	if (!mayGet()) {
		throw GetAuthError(KADM5_AUTH_GET);
	}
	
	auto_ptr< vector<string> > names( listPrincipals(filter) );
	vector<Principal*>* ret = new vector<Principal*>;
	
	for (
		vector<string>::const_iterator it = names->begin();
		it != names->end();
		it++
	) {
		ret->push_back(new Principal(_context.get(), *it));
	}
	
	return ret;
}


std::vector<string>* Connection::listPrincipals(const string& filter) const
{
	char** list = NULL;
	int count = 0;
	vector<string>* ret = NULL;
	
	if (!mayList()) {
		throw ListAuthError(KADM5_AUTH_LIST);
	}
	
	try {
		_context->getPrincipals(filter.c_str(), &list, &count);
		
		// Initialize vector with the list of principal names
		// (use char** pointer as iterator).
		ret = new vector<string>(list, list + count);
	} catch (...) {
		if (list) {
			_context->freeNameList(list, &count);
		}
		delete ret;
		throw;
	}
	
	return ret;
}


bool Connection::hasPrivilege(u_int32_t privilegeFlags) const
{
	u_int32_t p;
	
	_context->getPrivs(&p);
	
	return (privilegeFlags & p) == privilegeFlags;
}


}
