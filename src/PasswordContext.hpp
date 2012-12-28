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


#ifndef PASSWORDCONTEXT_HPP_
#define PASSWORDCONTEXT_HPP_

// STL and Boost
#include <string>

// Local
#include "Context.hpp"

namespace kadm5
{

using std::string;

/**
 * \brief
 * Kerberos and KAdmin Context using password authentication.
 * 
 * \author Peter Dinges <pdinges@acm.org>
 **/
class PasswordContext : public Context
{
public:
	/**
	 * Constructs a new PasswordContext from the given connection data.
	 * 
	 * \param	password	Connect to the KAdmin server using
	 * 			this password.
	 * \param	client	The name of the Kerberos principal to
	 * 			authenticate as. If missing, the libraries'
	 * 			default value will be used.
	 * \param	realm	The realm to assume if this part of a
	 * 			Principal's name is omitted. If missing,
	 * 			the libraries' default value will be used.
	 * \param	host	Hostname of the KAdmin server to connect to.
	 * 			If missing, defaults to the
	 * 			<code>admin_server</code> parameter in the
	 * 			Kerberos configuration.
	 * \param	port	The KAdmin server's port number.
	 * 			If <code>0</code>, uses the libraries' default
	 * 			port number.
	 **/
	explicit PasswordContext(
		const string& password,
		const string& client,
		const string& realm,
		const string& host,
		const int port
	);
};

} /* namespace kadm5 */

#endif /*PASSWORDCONTEXT_HPP_*/
