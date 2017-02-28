all: cmtp_server cmtp_client cmtp_adduser

#General flags
CC = cc
OBJECTS = cmtp_common.o client_functions.o server_functions.o
CLIENT_SOURCE = source/cmtp_client.c source/cmtp_common.c source/client_functions.c include/base64.c
SERVER_SOURCE = source/cmtp_server.c source/cmtp_common.c source/server_functions.c include/base64.c
EDITOR_SOURCE = source/cmtp_client.c source/cmtp_common.c source/client_functions.c source/cmtp_server.c source/cmtp_common.c source/server_functions.c source/cmtp_adduser.c source/cmtp_common.c
UTIL_SOURCE = source/cmtp_adduser.c source/cmtp_common.c include/base64.c
HEADERS = source/server_functions.h source/client_functions.h source/cmtp_common.h include/base64.h
SERVER_LIBS = -lsodium -lresolv -lldns -lconfuse -lpthread
CLIENT_LIBS = -lsodium -lresolv -lldns
UTIL_LIBS = -lsodium -lresolv -lldns
CFLAGS=-g -std=c99 -Wall -Wextra -pedantic -pipe -O0

#Linux specific flags
ifeq ($(shell uname -s), Linux)
CFLAGS+=-D_GNU_SOURCE
endif

#MacOS specific flags
ifeq ($(shell uname -s), Darwin)
CFLAGS+=-I/opt/local/include -L/opt/local/lib -I/usr/include/machine/
endif

cmtp_server: $(SERVER_SOURCE)
ifndef nodebug
	mkdir -p bin
	$(CC) $(SERVER_SOURCE) $(CFLAGS) -DDEBUG=true $(SERVER_LIBS) -o bin/cmtp_server
	@echo $@ made in debug mode
else
	mkdir -p bin
	$(CC) $(SERVER_SOURCE) $(CFLAGS) $(SERVER_LIBS) -o bin/cmtp_server
	@echo $@ made
endif

cmtp_client: $(CLIENT_SOURCE)
ifndef nodebug
	mkdir -p bin
	$(CC) $(CLIENT_SOURCE)  $(CFLAGS) -DDEBUG=true $(CLIENT_LIBS) -o bin/cmtp_client
	@echo $@ made in debug mode
else
	mkdir -p bin
	$(CC) $(CLIENT_SOURCE) $(CFLAGS) $(CLIENT_LIBS) -o bin/cmtp_client
	@echo $@ made
endif

cmtp_adduser: $(UTIL_SOURCE)
ifndef nodebug
	mkdir -p bin
	$(CC) $(UTIL_SOURCE) $(CFLAGS) -DDEBUG=true $(UTIL_LIBS) -o bin/cmtp_adduser
	@echo $@ made in debug mode
else
	mkdir -p bin
	$(CC) $(UTIL_SOURCE) $(CFLAGS) $(UTIL_LIBS) -o bin/cmtp_adduser
	@echo $@ made
endif

base64: include/base64.c include/base64.h
	$(CC) -g include/base64.c $(CFLAGS)

open:
	atom $(CLIENT_SOURCE) $(SERVER_SOURCE) $(HEADERS) makefile

clean:
	rm -f bin/*
