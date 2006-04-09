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

#include "PasswordGenerator.hpp"

#include <boost/nondet_random.hpp>

#include "Error.hpp"

namespace KAdm5
{

PasswordGenerator::PasswordGenerator()
{
	CharacterClass cc[] = PWGEN_DEFAULT_CHARACTER_CLASSES;

	for (int i=0; i < PWGEN_DEFAULT_CHARACTER_CLASSES_COUNT; i++) {
		_characterClasses.push_back(cc[i]);
	}
}


PasswordGenerator::PasswordGenerator(const vector<CharacterClass>& characterClasses)
	:	_characterClasses(characterClasses)
{
	if (!characterClasses.size()) {
		throw ParamError(0);
	}
}


string PasswordGenerator::randomPassword() const
{
	boost::random_device rng;
	string random_chars;

	// Generate a list of random characters with the specified frequencies.
	for (int i=0; i < _characterClasses.size(); i++) {
		for (int j=0; j < _characterClasses[i].frequency; j++) {
			random_chars += _characterClasses[i].charset[ rng() % _characterClasses[i].charset.size() ];
		}
	}
	
	string pw;
	
	// Put the random characters at random positions in the password.
	while (random_chars.size()) {
		string::iterator it = random_chars.begin() + (rng() % random_chars.size());
		pw += *it;
		random_chars.erase(it);
	}
	
	return pw;
}


}
