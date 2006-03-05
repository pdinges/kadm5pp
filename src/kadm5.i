%module kadm5 
%include "std_string.i"
%include "std_vector.i"

%{

#include "Error.hpp"
#include "AdmContext.hpp"
#include "KrbContext.hpp"
#include "Principal.hpp"
#include "Connection.hpp"

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>

%}

// Instantiate templates used
namespace std {
   %template(StringVector) vector<string>;
   %template(PrincipalPVector) vector<KAdm5::Principal*>;
}

%exception {
	try {
		$action
	}
	catch (KAdm5::Error& e) {
		PyErr_SetString(PyExc_RuntimeError, strerror(e.getErrorCode()));

//		PyObject* p = SWIG_NewPointerObj((void *) &e, SWIGTYPE_p_KAdm5__Error, 1);
//		PyObject* c = PyErr_NewException("kadm5.Error", NULL, NULL);
//		PyErr_SetObject(c, p);
//		Py_DECREF(p);
//		Py_DECREF(c);
		return NULL;
	}
}

%typemap(python, out) boost::posix_time::ptime {
	boost::posix_time::ptime epoch(boost::gregorian::date(1970,1,1));
	boost::posix_time::time_duration d = $1 - epoch;
	$result = PyInt_FromLong((long) d.total_seconds());
}

%typemap(python, in) const boost::posix_time::ptime& {
	boost::posix_time::ptime* p = new boost::posix_time::ptime(boost::posix_time::from_time_t((long) PyInt_AsLong($input)));
	$1 = p;
}

%typemap(python, freearg) const boost::posix_time::ptime& {
	delete (boost::posix_time::ptime*) $1;
}

typedef	int int32_t;
typedef	unsigned int u_int32_t;

%include "Error.hpp"
%include "AdmContext.hpp"
%include "KrbContext.hpp"
%include "Principal.hpp"
%include "Connection.hpp"
