objects = Error.o Context.o PasswordContext.o Connection.o Principal.o

.PHONY: clean

all: _kadm5.so

_kadm5.so: kadm5_wrap.o $(objects)
	gcc -shared $^ -fPIC -o $@ -lkrb5 -lkadm5clnt -lboost_date_time

%_wrap.o: %_wrap.cxx
	gcc -c -fPIC -I/usr/include/python2.4/ -o $@ $<

%.o: %.cpp %.hpp
	gcc -c -fPIC -o $@ $<

kadm5_wrap.cxx: kadm5.i $(objects:.o=.hpp) $(objects:.o=.cpp)
	swig -c++ -python $<

clean:
	rm -f kadm5.py *.pyc *.pyo *_wrap.* *.so *.o *~
