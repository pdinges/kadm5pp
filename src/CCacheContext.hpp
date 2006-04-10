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

#ifndef CCACHECONTEXT_HPP_
#define CCACHECONTEXT_HPP_

// STL and Boost
#include <string>

// Kerberos
#include <krb5.h>

// Local
#include "Context.hpp"

namespace kadm5
{

//using boost::shared_ptr;
using std::string;

/**
 * \brief
 * Kerberos and KAdmin Context using credentials from a cache for
 * authentication.
 * 
 * \author Peter Dinges <me@elwedgo.de>
 **/
class CCacheContext : public Context
{
public:
	/**
	 * Constructs a new CCacheContext with the given connection data.
	 * 
	 * \param	ccname	Use credentials from this cache. The name may
	 * 			be a filename or any other valid identifier
	 * 			of form <code>TYPE:ID</code> understood by the
	 * 			libraries. If <code>TYPE:</code> is omitted,
	 * 			<code>FILE:</code> is assumed.
	 * \param	realm	The Kerberos realm for this context (will be
	 * 			used as default for all principals if no
	 * 			realm was specified).
	 * 			If empty, the default realm will be used.
	 * \param	host	The KAdmin server's hostname to connect to.
	 * 			If empty, the used realm's
	 * 			<code>admin_server</code> config parameter
	 * 			will be used.
	 * \param	port	The KAdmin server's port number.
	 * 			If <code>0</code>, use the libraries' default
	 * 			port number.
	 * 
	 * \todo	Check for empty password and throw exception.
	 **/
	explicit CCacheContext(
		const string& ccname,
		const string& realm,
		const string& host,
		const int port
	);
	
	/**
	 * Releases all held resources.
	 **/
	virtual ~CCacheContext();

private:
	/** Used credential cache. */
	krb5_ccache _ccache;
};

} /* namespace kadm5 */

#endif /*CCACHECONTEXT_HPP_*/
