/******************************************************************************
 *                                                                            *
 *  Copyright (c) 2006 Peter Dinges <me@elwedgo.de>                           *
 *  All rights reserved.                                                      *
 *                                                                            *
 *  Redistribution and use in source and binary forms, with or without        *
 *  modification, are permitted provided that the following conditions        *
 *  are met:                                                                  *
 *                                                                            *
 *  1. Redistributions of source code must retain the above copyright         *
 *     notice, this list of conditions and the following disclaimer.          *
 *                                                                            *
 *  2. Redistributions in binary form must reproduce the above copyright      *
 *     notice, this list of conditions and the following disclaimer in the    *
 *     documentation and/or other materials provided with the distribution.   *
 *                                                                            *
 *  3. The name of the author may not be used to endorse or promote products  *
 *     derived from this software without specific prior written permission.  *
 *                                                                            *
 *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR      *
 *  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES *
 *  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.   *
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,          *
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT  *
 *  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, *
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY     *
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT       *
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF  *
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.         *
 *                                                                            *
 *****************************************************************************/
/* $Id$ */

// STL and Boost
#include <string>

// Kerberos
#include <krb5.h>
#include <kadm5/admin.h>

// Local
#include "CCacheContext.hpp"
#include "Error.hpp"

namespace kadm5
{
	
using std::string;

CCacheContext::CCacheContext(
	const string& ccname,
	const string& realm,
	const string& host,
	const int port
)	:	Context("", realm, host, port),
		_ccache(NULL)
{
	KADM5_DEBUG("CCacheContext::CCacheContext(): Constructing...\n");
	
	// Tricky: 'this' is not yet completely initialized so be careful(!)
	string f = ccname.empty() ? krb5_cc_default_name(*this) : ccname;
	if (f.find(":") == string::npos) {
		f.insert(0, "FILE:");
	}

	KADM5_DEBUG(
		"CCacheContext(): Opening credential cache '" + f + "'\n"
	);
	krb5_cc_resolve(*this, f.c_str(), &_ccache);
	
	// Test whether credential cache exists; kadm5_init_... won't do it.
	krb5_principal ptmp = NULL;
	error::throw_on_error( krb5_cc_get_principal(*this, _ccache, &ptmp) );
	krb5_free_principal(*this, ptmp);

	void* ph = NULL;
	error::throw_on_error(
		kadm5_init_with_creds_ctx(
			*this,
			NULL,
			_ccache,
			KADM5_ADMIN_SERVICE,
			config_params().get(),
			KADM5_STRUCT_VERSION,
			KADM5_API_VERSION_2,
			&ph
		)
	);
	set_kadm_handle( shared_ptr<void>(ph, kadm5_destroy) );
}


CCacheContext::~CCacheContext()
{
	// Tricky aswell: Context part of 'this' still exists right now.
	if (_ccache) {
		KADM5_DEBUG("~CCacheContext(): Closing credential cache\n");
		krb5_cc_close(*this, _ccache);
		_ccache = NULL;
	}
	KADM5_DEBUG("~CCacheContext(): Destructed.\n");	
}

} /* namespace kadm5 */
