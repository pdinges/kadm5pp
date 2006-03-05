#include "Connection.hpp"

#include <memory>

namespace KAdm5
{
using std::auto_ptr;


Connection::Connection(const string& realm, const string& host, const int port)
	:	_krbContext(NULL),
		_admContext(NULL)
{
	const char* r = NULL;
	const char* h = NULL;
	
	_krbContext = new KrbContext();
//	try {
		if (!realm.empty()) {
			r = realm.c_str();
		}
		if (!host.empty()) {
			h = host.c_str();
		}
		_admContext = _krbContext->createAdmContext(r, h, port);
//	}
//	catch (...) {
//		// Clean up if anything goes wrong.
//		delete _krbContext;
//		throw;
//	}
}


Connection::~Connection()
{
	// Pointers are NULL initialized so delete always works.
	delete _admContext;
	delete _krbContext;
}


Principal* Connection::createPrincipal(const string& name) const
{
	auto_ptr< vector<string> > existing( listPrincipals(name) );
	// TODO Differentiate between bad name and already existing principal
	if (existing->size() != 0) {
		throw PrincipalError(KADM5_BAD_PRINCIPAL);
	}
	
	return new Principal(name, _krbContext, _admContext);
}


void Connection::deletePrincipal(Principal* principal) const
{
//	_admContext->deletePrincipal(principal->)
}


Principal* Connection::getPrincipal(const string& name) const
{
	auto_ptr< vector<string> > candidates( listPrincipals(name) );
	
	// Unambiguous description suffices.
	if (candidates->size() == 1) {
		return new Principal(
			(*candidates)[0],
			_krbContext,
			_admContext
		);
	} else if (candidates->size() < 1) {
		throw UnknownPrincipalError(KADM5_UNK_PRINC);
	} else {
		throw AmbiguousKeyError(KADM5_AMBIGUOUS_KEY);
	}
}


std::vector<Principal*>* Connection::getPrincipals(const string& filter) const
{
	auto_ptr< vector<string> > names( listPrincipals(filter) );
	vector<Principal*>* ret = new vector<Principal*>;
	
	for (
		vector<string>::const_iterator it = names->begin();
		it != names->end();
		it++
	) {
		ret->push_back(new Principal(*it, _krbContext, _admContext));
	}
	
	return ret;
}


std::vector<string>* Connection::listPrincipals(const string& filter) const
{
	char** list = NULL;
	int count = 0;
	vector<string>* ret = NULL;
	
	if (!mayList()) {
		// TODO throw Forbidden();
	}
	
	try {
		_admContext->getPrincipals(filter.c_str(), &list, &count);
		
		// Initialize vector with the list of principal names
		// (use char** pointer as iterator).
		ret = new vector<string>(list, list + count);
	} catch (...) {
		if (list) {
			_admContext->freeNameList(list, &count);
		}
		delete ret;
		throw;
	}
	
	return ret;
}


bool Connection::hasPrivilege(u_int32_t privilegeFlags) const
{
	u_int32_t p;
	
	_admContext->getPrivs(&p);
	
	return (privilegeFlags & p) == privilegeFlags;
}


}
