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
#include "cmtp_common.h"
#include "client_functions.h"

struct addrinfo * addr_res;
struct addrinfo * addr_result;

int main(int argc, char *argv[])
{
  int client_socket = 0;
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
  const char *host = argv[1];
  /*Steps:
  1. Take user as input arg[1]
  2. Check local system for user private keyBuffer
  3. Prompt user for password and decrypt password
  4. Prompt for recipient address
  5. Fork to prefered editor
  6. "send"
  */
}
