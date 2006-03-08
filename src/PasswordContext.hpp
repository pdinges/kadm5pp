#ifndef PASSWORDCONTEXT_HPP_
#define PASSWORDCONTEXT_HPP_

#include <krb5.h>

#include "Context.hpp"

namespace KAdm5
{

class PasswordContext : public Context
{
public:
	PasswordContext(const char*, const char* =NULL, const char* =NULL, const char* =NULL, const int =0);
};

}

#endif /*PASSWORDCONTEXT_HPP_*/
