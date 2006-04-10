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

#include <string>
#include <vector>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/python.hpp>
#include <boost/python/suite/indexing/vector_indexing_suite.hpp>
#include <boost/shared_ptr.hpp>

#include "Connection.hpp"
#include "Error.hpp"
#include "Principal.hpp"

namespace py=boost::python;
using boost::posix_time::ptime;
using boost::posix_time::time_duration;
using boost::shared_ptr;
using std::string;
using std::vector;

/*
 * Type converters
 */
struct ptime_to_int
{
	static PyObject* convert(ptime const& t)
	{
		ptime epoch(boost::gregorian::date(1970,1,1));
		time_duration d = t - epoch;
		return PyInt_FromLong((long) d.total_seconds());
	}
};


struct time_duration_to_int
{
	static PyObject* convert(time_duration const& d)
	{
		return PyInt_FromLong((long) d.total_seconds());
	}
};


BOOST_PYTHON_FUNCTION_OVERLOADS(
	Connection_from_password_overloads,
	kadm5::Connection::from_password,
	1, 5
);


/*
 * Exceptions
 */



//static py::handle<> error_type;

//static py::object Foo;
////static py::object Bar;
////void translator(const kadm5::Error& e) {
////    PyErr_SetString(Bar.ptr(), "I'm sorry Dave...");
////}
//
//void translator(const kadm5::error& e)
//{
////	static py::object py_exception_class((
////		py::handle<>(py::borrowed(PyExc_EOFError))
////	));
// 
////	PyErr_SetString(py_exception_class.ptr(), "My message"); 
////	PyErr_SetString(Foo.ptr(), "My message");
//
////	static py::object py_exception_class2((
////		py::handle<>( PyErr_NewException("kadm5.Error2", py_exception_class.ptr(), NULL) )
////	));
////
////	static py::object Bar( Foo(e.error_code()) );
////	
////	PyErr_SetObject(py_exception_class2.ptr(), Bar.ptr());
//
//	py::object exception( Foo(e.error_code()) );
//	
//	PyErr_SetObject(exception_type.get(), exception.ptr());
//}



BOOST_PYTHON_MODULE(kadm5)
{
	/*
	 * Return types
	 */
	py::register_ptr_to_python< shared_ptr<kadm5::Connection> >();
	py::register_ptr_to_python< shared_ptr<kadm5::Principal> >();
	py::register_ptr_to_python< shared_ptr< vector<string> > >();
	py::register_ptr_to_python< shared_ptr< vector< shared_ptr<kadm5::Principal> > > >();

	py::class_< vector<string> >("StringVector")
		.def(py::vector_indexing_suite< vector<string>, true >())
	;
	py::class_< vector< shared_ptr<kadm5::Principal> > >("PrincipalVector")
		.def(
			py::vector_indexing_suite<
				vector< shared_ptr<kadm5::Principal> >,
				true
			>()
		)
	;
	
	py::to_python_converter<ptime, ptime_to_int>();
	py::to_python_converter<time_duration, time_duration_to_int>();
//	
//py::object Bar( py::class_<kadm5::Error>("Error", py::init<u_int32_t>())
//	.def("error_code", &kadm5::Error::error_code)
//);

////py::tuple t = py::extract<py::tuple>(Bar.attr("__bases__"));
//////t += py::make_tuple( (py::handle<>(py::borrowed(PyExc_EOFError))) );
////
////py::extract<py::tuple>(Bar.attr("__bases__")) = py::make_tuple(
////	t[0],
////	(py::handle<>(py::borrowed(PyExc_EOFError)))
////);
//
//	Foo = Bar;

//	error_type( PyErr_NewException("kadm5.Error", NULL, NULL) );
//	py::handle<> module_dict( PyModule_GetDict(


	
//	py::register_exception_translator<kadm5::Error>(translator);
	
	
	/*
	 * Connection
	 */
	py::class_<kadm5::Connection, boost::noncopyable>("Connection", py::no_init)
		.def("create_principal", &kadm5::Connection::create_principal)
		.def("delete_principal", &kadm5::Connection::delete_principal)

		.def("get_principal", &kadm5::Connection::get_principal)
		.def("get_principals", &kadm5::Connection::get_principals)
		.def("list_principals", &kadm5::Connection::list_principals)

		.add_property("may_get", &kadm5::Connection::may_get)
		.add_property("may_add", &kadm5::Connection::may_add)
		.add_property("may_modify", &kadm5::Connection::may_modify)
		.add_property("may_delete", &kadm5::Connection::may_delete)
		.add_property("may_list", &kadm5::Connection::may_list)
		.add_property("may_change_password", &kadm5::Connection::may_change_password)
		.add_property("may_all", &kadm5::Connection::may_all)

		.add_property("client", &kadm5::Connection::client)
		.add_property("realm", &kadm5::Connection::realm)
		.add_property("host", &kadm5::Connection::host)
		.add_property("port", &kadm5::Connection::port)

		/* Factory methods */
		.def(
			"from_password",
			kadm5::Connection::from_password,
			Connection_from_password_overloads()
		)
		.staticmethod("from_password")
	;
	
	/*
	 * Principal
	 */
	py::class_<kadm5::Principal>("Principal", py::no_init)
		.add_property(
			"exists_on_server",
			&kadm5::Principal::exists_on_server
		)
		.add_property("modified", &kadm5::Principal::modified)
		.def(
			"commit_modifications",
			&kadm5::Principal::commit_modifications
		)
		
		.add_property("id", &kadm5::Principal::id)
		.add_property(
			"name",
			&kadm5::Principal::name,
			&kadm5::Principal::set_name
		)
		.def("set_password", &kadm5::Principal::set_password)
//		.def("randomize_password")
//		.def("randomize_keys")
		
		.add_property(
			"expire_time",
			&kadm5::Principal::expire_time,
			&kadm5::Principal::set_expire_time
		)
		.add_property(
			"password_expiration",
			&kadm5::Principal::password_expiration,
			&kadm5::Principal::set_password_expiration
		)
		.add_property(
			"max_lifetime",
			&kadm5::Principal::max_lifetime,
			&kadm5::Principal::set_max_lifetime
		)
		.add_property(
			"max_renewable_lifetime",
			&kadm5::Principal::max_renewable_lifetime,
			&kadm5::Principal::set_max_renewable_lifetime
		)
//		.add_property(
//			"key_version",
//			&kadm5::Principal::key_version,
//			&kadm5::Principal::set_key_version
//		)
//		.add_property("policy")
		.add_property("modify_time", &kadm5::Principal::modify_time)
		.add_property(
			"last_password_change",
			&kadm5::Principal::last_password_change
		)
		.add_property("last_success", &kadm5::Principal::last_success)
		.add_property("last_failed", &kadm5::Principal::last_failed)
	;
	
}
