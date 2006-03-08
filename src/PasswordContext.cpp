#include "PasswordContext.hpp"

#include "Error.hpp"

namespace KAdm5
{

PasswordContext::PasswordContext(
	const char* password,
	const char* client,
	const char* realm,
	const char* host,
	const int port
)	:	Context(realm, host, port)
{
	if (!password) {
		throw ParamError(0);
	}
	
	// Create server handle.		
	Error::checkReturnVal(
		kadm5_init_with_password_ctx(
			_krb_context,
			client,
			password,
			KADM5_ADMIN_SERVICE,
			_config_params,
			KADM5_STRUCT_VERSION,
			KADM5_API_VERSION_2,
			&_kadm_handle
		)
	);
}


}
