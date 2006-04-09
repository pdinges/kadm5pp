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

#ifndef PASSWORDGENERATOR_HPP_
#define PASSWORDGENERATOR_HPP_

#include <string>
#include <vector>

#define PWGEN_DEFAULT_CHARACTER_CLASSES { \
	{ "abcdefghijklmnopqrstuvwxyz", 7 }, \
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 2 }, \
	{ "@$%&*()-+=:,/<>1234567890" , 1 }, \
}
#define PWGEN_DEFAULT_CHARACTER_CLASSES_COUNT 3


namespace KAdm5
{
using std::string;
using std::vector;


struct CharacterClass {
	string charset;
	int frequency;
};

// TODO Refactor this class, maybe remove it altogether
// and use a global function?
class PasswordGenerator
{
public:
	PasswordGenerator();
	PasswordGenerator(const std::vector<CharacterClass>&);
	string randomPassword() const;

private:
	vector<CharacterClass> _characterClasses;
};

}

#endif /*PASSWORDGENERATOR_HPP_*/
