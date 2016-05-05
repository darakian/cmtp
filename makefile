all: cmtp_server cmtp_client

CC = gcc
OBJECTS = cmtp_common.o client_functions.o server_functions.o
CLIENT_SOURCE = source/cmtp_client.c source/cmtp_common.c source/client_functions.c include/base64.c
SERVER_SOURCE = source/cmtp_server.c source/cmtp_common.c source/server_functions.c include/base64.c
UTIL_SOURCE = source/cmtp_adduser.c source/cmtp_common.c include/base64.c
HEADERS = source/server_functions.h source/client_functions.h source/cmtp_common.h include/base64.h
SERVER_LIBS = -lsodium -lresolv -lconfuse -lpthread
CLIENT_LIBS = -lsodium -lresolv
UTIL_LIBS = -lsodium
CFLAGS=-g -Wall -Wextra -pedantic -pipe -O0


#The -D_GNU_SOURCE option is used for the linux binary only and is needed for the set_privilage function.
#A BSD build would provide the same dependencies via unistd.h
cmtp_server: $(SERVER_SOURCE)
ifndef nodebug
	mkdir -p bin
	$(CC) $(SERVER_SOURCE) $(CFLAGS) -DDEBUG=true -D_GNU_SOURCE $(SERVER_LIBS) -o bin/cmtp_server
	@echo $@ made in debug mode
else
	mkdir -p bin
	$(CC) $(SERVER_SOURCE) $(CFLAGS) -D_GNU_SOURCE $(SERVER_LIBS) -o bin/cmtp_server
	@echo $@ made
endif

cmtp_client: $(CLIENT_SOURCE)
ifndef nodebug
	mkdir -p bin
	$(CC) $(CLIENT_SOURCE) $(CFLAGS) -D_GNU_SOURCE -DDEBUG=true $(CLIENT_LIBS) -o bin/cmtp_client
	@echo $@ made in debug mode
else
	mkdir -p bin
	$(CC) $(CLIENT_SOURCE) $(CFLAGS) -D_GNU_SOURCE $(CLIENT_LIBS) -o bin/cmtp_client
	@echo $@ made
endif

cmtp_adduser: $(UTIL_SOURCE)
ifndef nodebug
	mkdir -p bin
	$(CC) $(UTIL_SOURCE) $(CFLAGS) -D_GNU_SOURCE -DDEBUG=true $(UTIL_LIBS) -o bin/cmtp_adduser
	@echo $@ made in debug mode
else
	mkdir -p bin
	$(CC) $(UTIL_SOURCE) $(CFLAGS) -D_GNU_SOURCE $(UTIL_LIBS) -o bin/cmtp_adduser
	@echo $@ made
endif

base64: include/base64.c include/base64.h
	$(CC) -g include/base64.c $(CFLAGS)

clean:
	rm bin/*
