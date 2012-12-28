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


#ifndef CONTEXTTEST_HPP_
#define CONTEXTTEST_HPP_

// CppUnit
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

// Local
#include "../Context.hpp"

namespace kadm5
{
namespace _test
{

class ContextTest : public  CPPUNIT_NS::TestFixture
{
	CPPUNIT_TEST_SUITE( ContextTest );
	CPPUNIT_TEST( testTypeConversion );
	CPPUNIT_TEST( testRealm );
	CPPUNIT_TEST( testClient );
	CPPUNIT_TEST( testHost );
	CPPUNIT_TEST( testPort );
	CPPUNIT_TEST_SUITE_END();

protected:
	void testTypeConversion();
	void testRealm();
	void testClient();
	void testHost();
	void testPort();
};

} /* namespace _test */
} /* namespace kadm5 */

#endif /*CONTEXTTEST_HPP_*/
