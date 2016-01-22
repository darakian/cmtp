/*Include guard*/
#ifndef _serverfunctions_h
#define _serverfunctions_h

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#define SERVER_PORT 9001
#define MAX_CONNECTIONS 10
#define CMTP_VERSION '1'
#define MAIL_READ_BUFFER 1
#define CMTP_DIRECTORY /var/cmtp


struct connection_manager_structure
{
  int connection_file_descriptor;
};

/*
All functions that follow can fail and must fail in an acceptible way (-1 as return value)
*/

int server_init();

int forwardMessage(char * messageBuffer, long messageLength, char * dest_server, int dest_server_length);

int sendKey(char * dest_server, int dest_server_length, char * user);

/*server and server length should probably be a resolved IP structure... maybe*/
int requestKey(char * recieve_buffer, int recieve_length, char * account_requested, int request_length, char * server, int server_length);

/*Accept message should pass the message to the CMAP backend*/
int acceptMessage();

void connection_manager(void * connection_manager_argument);

int select_available_socket(int * connections, int number_of_connections);


#endif /* _serverfunctions_h */
