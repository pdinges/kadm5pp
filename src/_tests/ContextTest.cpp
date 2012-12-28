/******************************************************************************
 *                                                                            *
 *  Copyright (c) 2006 Peter Dinges <pdinges@acm.org>                           *
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


// System libs for tests
#include <stdlib.h>

// Kerberos
#include <krb5.h>

// Local
#include "../Context.hpp"
#include "../Error.hpp"
#include "ContextTest.hpp"


CPPUNIT_TEST_SUITE_REGISTRATION (kadm5::_test::ContextTest);


namespace kadm5
{
namespace _test
{

/**
 * \brief
 * Helper class to gain access to Context's protected constructor.
 **/
class ContextExpose : public kadm5::Context
{
public:
	explicit ContextExpose(
		const string& client,
		const string& realm,
		const string& host,
		const int port
	)	:	Context(client, realm, host, port)
	{}
};




void ContextTest::testTypeConversion()
{
	ContextExpose c("client", "REALM", "host", 42);
	krb5_realm r = NULL;

	CPPUNIT_ASSERT_MESSAGE(
		"Could not use Context object as krb5_context. "
		"(Maybe ./data/krb5.conf does not set a default_realm?)",
		krb5_get_default_realm(c, &r) == 0
	);
	free(r);
}


void ContextTest::testRealm()
{
	ContextExpose c("", "", "", 0);
	CPPUNIT_ASSERT_MESSAGE(
		"Default realm is not 'TEST.LOCAL'. "
		"(Maybe ./data/krb5.conf has wrong default_realm?)",
		c.realm() == "TEST.LOCAL"
	);

	ContextExpose c2("", "CUSTOM.REALM", "custom.kadmin.server", 0);
	CPPUNIT_ASSERT_MESSAGE(
		"Custom realm name differs from input.",
		c2.realm() == "CUSTOM.REALM"
	);
}


void ContextTest::testClient()
{
	std::string u( getenv("LOGNAME") );

	// Default principal expected by KAdmind is '<currentuser>/admin'.
	// Note: '/admin'-context is enforced by KAdmind.
	ContextExpose c( "", "", "", 0 );
	CPPUNIT_ASSERT_MESSAGE(
		"Default user is not '<currentuser>/admin'",
		c.client() == u + "/admin@" + c.realm()
	);
	
	ContextExpose c2( "user", "", "", 0 );
	CPPUNIT_ASSERT_MESSAGE(
		"Plain username is not returned with '/admin'-context.",
		c2.client() == "user/admin@" + c.realm()
	);
	
	ContextExpose c3( "user/context", "", "", 0 );
	CPPUNIT_ASSERT_MESSAGE(
		"Custom context is not overwritten with '/admin'.",
		c3.client() == "user/admin@" + c.realm()
	);
	
	ContextExpose c4( "user@OTHER.REALM", "", "", 0 );
	CPPUNIT_ASSERT_MESSAGE(
		"Plain username is not returned with '/admin'-context (w/ REALM).",
		c4.client() == "user/admin@OTHER.REALM"
	);

	ContextExpose c5( "user/context@OTHER.REALM", "", "", 0 );
	CPPUNIT_ASSERT_MESSAGE(
		"Custom context is not overwritten with '/admin' (w/ REALM).",
		c5.client() == "user/admin@OTHER.REALM"
	);

	ContextExpose c6( "user/admin@OTHER.REALM", "", "", 0 );
	CPPUNIT_ASSERT_MESSAGE(
		"Custom complete principal returned differs from input.",
		c6.client() == "user/admin@OTHER.REALM"
	);
	
}


void ContextTest::testHost()
{
	ContextExpose c("", "", "", 0);
	CPPUNIT_ASSERT_MESSAGE(
		"Default host for default realm is not '127.0.0.1'. "
		"(Maybe ./data/krb5.conf has wrong admin_server?)",
		c.host() == "127.0.0.1"
	);
	
	ContextExpose c2("", "", "custom.host", 0);
	CPPUNIT_ASSERT_MESSAGE(
		"Custom host differs from input.",
		c2.host() == "custom.host"
	);
	
	ContextExpose c3("", "", "custom.host:42", 0);
	CPPUNIT_ASSERT_MESSAGE(
		"Specifying 'host:port' as host makes returned value differ "
		"from 'host'.",
		c3.host() == "custom.host"
	);
	
	// Contexts for unknown realms need to have a host specified since we
	// cannot guess its name.
	CPPUNIT_ASSERT_THROW(
		ContextExpose c4("", "UNKNOWN.REALM", "", 0),
		kadm5::bad_server
	);
}


void ContextTest::testPort()
{
	ContextExpose c("", "", "", 0);
	CPPUNIT_ASSERT_MESSAGE(
		"Default port for default realm not 16749. "
		"(Maybe ./data/krb5.conf admin_server does not specify a port?)",
		c.port() == 16749
	);
	
	ContextExpose c2("", "UNKNOWN.REALM", "", 0);
	CPPUNIT_ASSERT_MESSAGE(
		"Default port for unknown realm ist not 749.",
		c2.port() == 749
	);
	
	ContextExpose c3("", "", "", 42);
	CPPUNIT_ASSERT_MESSAGE(
		"Custom port differs from input.",
		c3.port() == 42
	);
	
	ContextExpose c4("", "", "host:42", 0);
	CPPUNIT_ASSERT_MESSAGE(
		"Setting port in host string does not work.",
		c4.port() == 42
	);
	
	// Setting a port in the hostname string overrides the other setting
	// (as specified in MIT's KAdmin API Documentation, Section 4.3
	// "Configuration parameters" under "admin_server").
	ContextExpose c5("", "", "host:42", 17);
	CPPUNIT_ASSERT_MESSAGE(
		"Setting port in host string does not override extra parameter.",
		c5.port() == 42
	);
}

} /* namespace _test */
} /* namespace kadm5 */
