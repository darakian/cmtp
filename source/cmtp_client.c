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

#include <sodium.h>

//Make common.h
#include "cmtp_common.h"
#include "client_functions.h"

struct addrinfo * addr_res;
struct addrinfo * addr_result;

int main(int argc, char *argv[])
{
  ns_msg msg;
  ns_rr rr;
  int res_length = 0;
  struct sockaddr_in * insock;
  struct sockaddr_storage sock_storage;
  // if (sodium_init()==-1)
  // {
  //   perror("Crypto error");
  //   return -1;
  // }

  // int file_descriptor;
  // file_descriptor = open(argv[1], O_RDONLY);
  // res_init();
  const char *host = argv[1];
  int ohana = resolve_server(argv[1], &sock_storage);
  if (ohana==AF_INET)
  {
    insock = (struct sockaddr_in *) (&sock_storage);
    if (insock->sin_port==0)
    {
      printf("Setting port of insock\n" );
      insock->sin_port=25;
    }
    printf("insock.sin_family = %d\n",insock->sin_family);
    printf("insock.sin_port = %d\n", insock->sin_port);
    printf("insock hostname ->  %s\n", inet_ntoa(insock->sin_addr));

  }
  else if (ohana==AF_INET6)
  {
    struct sockaddr_in6 * insock6 = (struct sockaddr_in6 *) (&sock_storage);
    //Do some ipv6 things
  }

  if (client_init()!=1)
  {
    perror("Client socket init has failed");
  }

  connect_remoteV4(insock);




}
