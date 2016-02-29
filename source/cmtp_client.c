#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <syslog.h>

#include <sodium.h>

//Make common.h
#include "../include/base64.h"
#include "cmtp_common.h"
#include "client_functions.h"

struct addrinfo * addr_res;
struct addrinfo * addr_result;

int main(int argc, char *argv[])
{
  if (argc != 2)
  {
    printf("Usage: cmtp_client <USERNAME>\n");
    exit(1);
  }
  int client_socket = 0;
  char user_key_path[400] = {0};
  char * local_user = argv[1];
  char base64_username[341] = {0};



  if ((client_socket = client_init())<0)
  {
    perror("client init");
    print_to_log("Client init failed. Terminating", LOG_CRIT);
    exit(1);
  }
  ns_msg msg;
  ns_rr rr;
  int res_length = 0;
  struct sockaddr_in * insock;
  struct sockaddr_storage sock_storage;
  /*Steps:
  1. Take user as input arg[1]
  2. Check local system for user private keyBuffer
  3. Prompt user for password and decrypt password
  4. Prompt for recipient address
  5. Fork to prefered editor
  6. "send"
  */
  if (strlen(local_user)>255)
  {
    perror("Username too long");
    print_to_log("Username too long. Exiting.", LOG_CRIT);
    exit(1);
  }
  uint32_t base64_username_length = base64_encode((char *)local_user, sizeof(local_user), base64_username, sizeof(base64_username), (char *)filesystem_safe_base64_string, 64);
  snprintf(user_key_path, sizeof(user_key_path), "%s%s%s", "/var/cmtp/mail/", base64_username, "/private.key");
  if (access(user_key_path, R_OK)<0)
  {
    #ifdef DEBUG
    printf("Cannot access the file at %s\n", user_key_path);
    #endif /*DEBUG*/
    perror("Access to private key failed. Aborting");
    print_to_log("Access to private key failed. Aborting", LOG_CRIT);
    exit(1);
  }
}
