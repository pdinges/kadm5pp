#ifndef PRINCIPAL_H_
#define PRINCIPAL_H_

#include <string>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "Context.hpp"


namespace KAdm5
{
using std::string;
using boost::posix_time::ptime;
using boost::posix_time::time_duration;

class Principal
{
public:
	Principal(Context*, const string&, const string& ="");
	~Principal();

	bool existsOnServer() const;
	bool wasModified() const;
	void commitChanges();
	
	string getId() const;
	string getName() const;
	void setName(const string&);
	void setPassword(const string&);
//	void randomizeKeys();
	
	
	ptime getExpireTime() const;
	void setExpireTime(const ptime&);
//	void setExpireTime(string);
	
	ptime getPasswordExpiration() const;
	void setPasswordExpiration(const ptime&);
	
	time_duration getMaxLifetime() const;
	void setMaxLifetime(const time_duration&);

	time_duration getMaxRenewableLifetime() const;
	void setMaxRenewableLifetime(const time_duration&);

//	const u_int32_t getKeyVersion() const;
//	void setKeyVersion(u_int32_t);

//	const Policy* getPolicy() const;
//	void setPolicy(Policy*);

	Principal* getModifier() const;
	ptime getModifyTime() const;
	ptime getLastPasswordChange() const;
	ptime getLastSuccess() const;
	ptime getLastFailed() const;
	
// TODO Implement accessors for the following kadm5_principal_ent_t members:
//    krb5_flags attributes;
//    u_int32_t aux_attributes;
//
//    krb5_kvno mkvno;
//
//    krb5_kvno fail_auth_count;
	

private:
	void load() const;
	void applyCreate() const;
	void applyRename();
	void applyModify() const;
	void applyPwChange() const;

	Context* _context;
	kadm5_principal_ent_t _data;
	krb5_principal _id;	// The kadmind knows this Principal under this name.
	mutable char* _password;
	mutable bool _loaded;
	mutable bool _exists;
	mutable u_int32_t _modifiedMask;
};

}

#endif /*PRINCIPAL_H_*/
