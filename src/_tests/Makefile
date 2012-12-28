#
# Use local kerberos configuration so we won't interfere with the system config
#
export KRB5_CONFIG=./data/krb5.conf
test-objects := $(patsubst %.cpp,%.o,$(shell ls *Test.cpp))
objects := $(patsubst %Test.o,../%.o,$(test-objects))

test: main ticket
	./main

main: main.o $(test-objects) $(objects) ../Error.o
	gcc -o $@ $^ -lkrb5 -lkadm5clnt -lcppunit

# Rely on parent-directories' Makefile for non-test object creation
../%.o:
	cd ..; make $(patsubst ../%.o,%.o,$@)

%.o: %.cpp %.hpp
	g++ -c -o $@ $<

# Create stash file
data/test.mkey:
	kstash --random-key --key-file=./data/test.mkey

# Create a principal database with known population
data/test.db: data/test.mkey
	kadmin --local \
		init --realm-max-ticket-life=1h --realm-max-renewable-life=4h TEST.LOCAL
	kadmin --local \
		add --use-defaults --password=admin user/admin

# Fetch a ticket with all administration privileges
# TODO: do not refetch ticket if still valid.
# TODO: remove required user interaction.
ticket: start-daemons
	kinit --no-addresses user/admin

start-daemons: data/test.db
	@start-stop-daemon --verbose --start --background --oknodo \
		--pidfile ./data/kdc.pid --make-pidfile --chdir . \
		--exec /usr/lib/heimdal-servers/kdc
	# With --background, kadmind silently quits. Therefore use &
	@start-stop-daemon --verbose --start --oknodo \
		--pidfile ./data/kadmind.pid --make-pidfile --chdir . \
		--exec /usr/lib/heimdal-servers/kadmind -- --ports=16749 &

stop-daemons:
	@start-stop-daemon --verbose --stop --pidfile ./data/kdc.pid --oknodo && \
		rm -f ./data/kdc.pid
	@start-stop-daemon --verbose --stop --pidfile ./data/kadmind.pid --oknodo && \
		rm -f ./data/kadmind.pid

clean: stop-daemons
	rm -f *.o main
	rm -f ./data/test.{db,mkey}
	kdestroy
