all: cmtp_server cmtp_client

OBJECTS = cmtp_common.o client_functions.o server_functions.o
CLIENT_SOURCE = source/cmtp_client.c source/cmtp_common.c source/client_functions.c include/base64.c
SERVER_SOURCE = source/cmtp_server.c source/cmtp_common.c source/server_functions.c include/base64.c
HEADERS = source/server_functions.h source/client_functions.h source/cmtp_common.h include/base64.h
CFLAGS=-g -Wall -Wextra -pedantic -pipe -O0


#The -D_GNU_SOURCE option is used for the linux binary only and is needed for the set_privilage function.
#A BSD build would provide the same dependencies via unistd.h
cmtp_server: $(SERVER_SOURCE)
ifndef nodebug
	mkdir -p bin
	gcc $(SERVER_SOURCE) $(CFLAGS) -DDEBUG=true -D_GNU_SOURCE -lsodium -lpthread -lresolv -o bin/cmtp_server
	@echo $@ made in debug mode
else
	mkdir -p bin
	gcc $(SERVER_SOURCE) $(CFLAGS) -D_GNU_SOURCE -lsodium -lpthread -lresolv -o bin/cmtp_server
	@echo $@ made
endif

cmtp_client: $(CLIENT_SOURCE)
ifndef nodebug
	mkdir -p bin
	gcc $(CLIENT_SOURCE) $(CFLAGS) -DDEBUG=true -lsodium -lresolv -o bin/cmtp_client
	@echo $@ made in debug mode
else
	mkdir -p bin
	gcc $(CLIENT_SOURCE) $(CFLAGS) -lsodium -lresolv -o bin/cmtp_client
	@echo $@ made
endif

base64: include/base64.c include/base64.h
	gcc -g include/base64.c $(CFLAGS)

clean:
	rm bin/* 
