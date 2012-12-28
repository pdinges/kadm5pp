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


#ifndef RANDOMPASSWORD_HPP_
#define RANDOMPASSWORD_HPP_

#include <string>
#include <vector>

/** Default character classes used for random password generation. */
// The { "", 0 } entry is used to determine the array end.
#define RANDOMPASSWORD_DEFAULT_CHARACTER_CLASSES { \
	{ "abcdefghijklmnopqrstuvwxyz", 7 }, \
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 2 }, \
	{ "@$%&*()-+=:,/<>1234567890" , 1 }, \
	{ "", 0 }, \
}


namespace kadm5
{

using std::string;
using std::vector;

/**
 * \brief
 * A character class used by the random password generator random_password().
 **/
struct CharClass {
	/** A string consisting of all characters in this class. */
	string charset;
	/**
	 * The frequency of characters in this class in the generated
	 * password (how often a character from this class will appear).
	 **/
	int frequency;
	
	/**
	 * A list of default CharClasses as used by the <code>kadmin</code>
	 * commandline program.
	 **/
	static const vector<CharClass>& defaults();	
};

/**
 * Generates a random password from the given list of character classes.
 * The resulting password's length will be the sum of the frequencies for all
 * character classes.
 * 
 * \note
 * This operation may block if the system's entropy pool is empty.
 * 
 * \param	ccl	A list of character classes to use for password
 * 			generation.
 * \return	A random password consisting of <code>sum(frequencies)</code>
 * 		characters from the given character classes (in random order).
 **/
const string random_password(
	const vector<CharClass>& ccl =CharClass::defaults()
);

} /* namespace kadm5 */

#endif /*RANDOMPASSWORD_HPP_*/
