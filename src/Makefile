#objects = Error.o PasswordGenerator.o Context.o PasswordContext.o Connection.o Principal.o
objects = Error.o Context.o PasswordContext.o CCacheContext.o Connection.o Principal.o kadm5.o

.PHONY: clean

all: kadm5.so

kadm5.so: $(objects)
	g++ -shared $^ -fPIC -o $@ -lkrb5 -lkadm5clnt -lboost_date_time -lboost_python

kadm5.o: kadm5.cpp
	g++ -c -fPIC -I/usr/include/python2.4/ -o $@ $<

%.o: %.cpp %.hpp
	g++ -c -fPIC -o $@ -DDEBUG $<

clean:
	rm -f kadm5.py *.pyc *.pyo *_wrap.* *.so *.o *~
