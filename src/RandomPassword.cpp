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
#include <boost/nondet_random.hpp>

// Local
#include "RandomPassword.hpp"
#include "Error.hpp"

namespace kadm5
{

const vector<CharClass>& CharClass::defaults()
{
	static vector<CharClass> ccl;

	if (ccl.empty()) {
		const CharClass cc[] =
			RANDOMPASSWORD_DEFAULT_CHARACTER_CLASSES;

		for (int i=0; !cc[i].charset.empty(); i++) {
			ccl.push_back(cc[i]);
		}
	}
	
	return ccl;
}


const string random_password(const vector<CharClass>& ccl)
{
	boost::random_device rng;
	string random_chars;

	// Generate a list of random characters with the specified frequencies.
	for (int i=0; i < ccl.size(); i++) {
		for (int j=0; j < ccl[i].frequency; j++) {
			random_chars += ccl[i].charset[
						rng() % ccl[i].charset.size()
					];
		}
	}
	
	string pw;
	
	// Put the random characters at random positions in the password.
	while (random_chars.size()) {
		string::iterator it = random_chars.begin() +
					(rng() % random_chars.size());
		pw += *it;
		random_chars.erase(it);
	}
	
	return pw;
}


} /* namespace kadm5 */
