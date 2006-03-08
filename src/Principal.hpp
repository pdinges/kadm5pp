#ifndef PRINCIPAL_H_
#define PRINCIPAL_H_

#include <string>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "Context.hpp"


namespace KAdm5
{
using std::string;
// TODO Add used boost classes

class Principal
{
public:
	Principal(const string&, Context*);
	~Principal();

	bool existsOnServer() throw(Error);
	bool wasModified();
	void commitChanges() throw(Error);
	
	string getId();
	string getName();
	void setName(const string&);
	void setPassword(const string&);
//	void randomizePassword();
	
	
	boost::posix_time::ptime getExpireTime();
	void setExpireTime(const boost::posix_time::ptime&);
//	void setExpireTime(string);
	
	boost::posix_time::ptime getLastPasswordChange();
	boost::posix_time::ptime getPasswordExpiration();
//	const krb5_deltat getMaxLifetime();
//	const krb5_deltat getMaxRenewableLifetime();

	Principal* getModifier();
	boost::posix_time::ptime getModifyTime();
	
//	const krb5_kvno getKeyVersion();
//	
//	string getPolicy();
	
	boost::posix_time::ptime getLastSuccess();
	boost::posix_time::ptime getLastFailed();
	
	
// TODO Implement accessors for the following kadm5_principal_ent_t members:
//    krb5_flags attributes;
//    u_int32_t aux_attributes;
//
//    krb5_kvno mkvno;
//
//    krb5_kvno fail_auth_count;
//    int16_t n_key_data;
//    int16_t n_tl_data;
//    krb5_tl_data *tl_data;
//    krb5_key_data *key_data;
	

private:
	void load();
	void applyCreate();
	void applyRename();

	Context* _context;
	kadm5_principal_ent_t _data;
	krb5_principal _id;	// The kadmind knows this Principal under this name.
	bool _loaded;
	bool _exists;
	u_int32_t _modifiedMask;
};

}

#endif /*PRINCIPAL_H_*/
