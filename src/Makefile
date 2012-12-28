objects := Error.o RandomPassword.o Context.o PasswordContext.o CCacheContext.o Connection.o Principal.o kadm5.o
include_dirs := $(shell python2-config --includes)
lib_dirs :=

.PHONY: clean

all: kadm5.so

kadm5.so: $(objects)
	g++ -shared $^ -fPIC $(lib_dirs) -o $@ -lkrb5 -lkadm5clnt -lboost_date_time -lboost_python -lboost_random

kadm5.o: kadm5.cpp
	g++ -c -fPIC $(include_dirs) -o $@ $<

%.o: %.cpp %.hpp
	g++ -c -fPIC $(include_dirs) -o $@ -DDEBUG $<

clean:
	rm -f kadm5.py *.pyc *.pyo *_wrap.* *.so *.o *~
