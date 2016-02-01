/*Include guard*/
#ifndef _serverfunctions_h
#define _serverfunctions_h

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <confuse.h>

#define LISTEN_PORT 9001
#define SEND_PORT 9002
#define MAX_CONNECTIONS 10
#define CMTP_VERSION '1'
#define MAIL_READ_BUFFER 1
#define CMTP_DIRECTORY /var/cmtp


struct connection_manager_structure
{
  int connection_file_descriptor;
};

//Need a struct to hold data filled in by parse_config function
struct config_struct {
  char domain[255];
  int connection_timeout_in_seconds;
};

/*
All functions that follow can fail and must fail in an acceptible way (-1 as return value)
*/

int server_init();

int forwardMessage(char * file_to_foward, char * dest_server_string);

int sendKey(char * dest_server, int dest_server_length, char * user);

/*server and server length should probably be a resolved IP structure... maybe*/
int requestKey(char * reveive_buffer, int reveive_length, char * account_requested, int request_length, char * server, int server_length);

/*Accept message should pass the message to the CMAP backend*/
int acceptMessage();

void * connection_manager(void * connection_manager_argument);

int select_available_socket(int * connections, int number_of_connections);

int parse_config(char * config_file, struct config_struct * running_config);

int process_server_mail(thread_connection, unique_file_name);


#endif /* _serverfunctions_h */
