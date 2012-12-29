kadm5pp
=======

The kadm5pp library provides an object-oriented interface to the
[Heimdal][heimdal]
[Kerberos&nbsp;5 administration libraries][kadm5].  It is written in
in C++ using [Boost][boost] and has an STL-style API.  It simplifies
the overall handling by automating context management and hiding the
exhausting C-style error handling behind exceptions.  It also tries to
motivate the right order of object use through its interface.

All objects are also exported to a [Python&nbsp;2][python] module
through Boost.Python.  Integration into Python makes scripting
administrative tasks more comfortable than calling the `kadmin`
command from shell scripts.

The library currently supports only a limited (but useful) set of
operations on the Kerberos database.  I have no intention of
developing the library any further and publish it here in the hope
that it might be useful to someone.


Installation
------------

Building the module requires the following:

* A C++ compiler and linker, as well as Make (`build-essential`)
* The [Heimdal][heimdal] Kerberos&nbsp;5 libraries and development
  headers (`heimdal-dev`).
  
  **Note:** The MIT Kerberos distribution will *not* work because the
  headers have different names and lack some of the used data
  structures.
* The [Boost][boost] library and associated headers (`libboost-dev`)

The name in parentheses after each item is the name of the
Debian/Ubuntu Linux package that contains the required files.  The
library has been verified to build against Heimdal&nbsp;1.5.2 and
Boost&nbsp;1.5.0.

Instead of installing Heimdal and Boost as system-wide libraries, you
can also compile and install them in a local directory.  Adjust the
`include_dirs` (`-I...`) and `lib_dirs` (`-L...`) variables in the
`Makefile` to tell the compiler about their locations.

After all dependencies have been installed, the kadm5pp library can
be built using Make.  Simply execute `make` in the `src/` directory.


Usage Example
-------------
The following Python code renames principal `foo` to `bar`:

~~~~{.py}
from kadm5 import Connection, Principal

c = Connection.from_password("adminpw")
p = c.get_principal("foo")
p.set_name("bar")
p.commit_modifications()
~~~~

See the [API documentation][kadm5pp-api] of the `Principal` class for
the same example in C++.


Copyright
---------

Copyright (c) 2006 Peter Dinges.  The kadm5pp library is open-source
software and is available under the [MIT License][mit-license].


[boost]: http://www.boost.org
  "Official website of the Boost C++ libraries"
[heimdal]: http://www.h5l.org/
  "The Heimdal Kerberos 5 implementation"
[mit-license]: http://opensource.org/licenses/mit-license.php
[kadm5]: http://cryptnet.net/mirrors/docs/krb5adm_api.html
  "HTML version of the Kerberos 5 Admin API specification"
[kadm5pp-api]: http://pdinges.github.com/kadm5pp
[python]: http://python.org
  "Official Python website"
