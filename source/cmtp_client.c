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

#include "../include/base64.h"
#include "cmtp_common.h"
#include "client_functions.h"

struct addrinfo * addr_res;
struct addrinfo * addr_result;

int main(int argc, char *argv[])
{
  if (argc != 3)
  {
    printf("Usage: cmtp_client <USERNAME> <DOMAIN>\n");
    exit(1);
  }
  int client_socket = 0;
  unsigned char user_key_buffer[sizeof(crypto_sign_ed25519_SECRETKEYBYTES)] = {0};
  char user_key_path[400] = {0};
  char * local_user = argv[1];
  char base64_username[341] = {0};
  char user_password[255] = {0};
  printf("Here\n");


  if ((client_socket = client_init())<0)
  {
    perror("client init");
    print_to_log("Client init failed. Terminating", LOG_CRIT);
    exit(1);
  }
  //request_key(client_socket, argv[1], argv[2], user_key_buffer);
  //ns_msg msg;
  //ns_rr rr;
  int res_length = 0;
  struct sockaddr_in * insock;
  struct sockaddr_storage sock_storage;
  printf("Password Please:\n");
  if (fgets(user_password, sizeof(user_password), stdin)==NULL)
  {
    perror("fgets");
  }
  //Exit if username exceeds CMTP limit
  if ((strlen(local_user)>255)||(strlen(user_password)<=0))
  {
    perror("Username too long or password too short");
    print_to_log("Username too long or password too short. Exiting.", LOG_CRIT);
    exit(1);
  }
  //Base64-ify the username
  uint32_t base64_username_length = base64_encode((char *)local_user, sizeof(local_user), base64_username, sizeof(base64_username), (char *)filesystem_safe_base64_string, 64);
  //Check for user private key. Perhaps this should be a call to LOGIN on the server
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

  char * temp_file = "/var/tmp/cmtp_compose";
  char recipient_user[256] = {0};
  char recipient_domain[256] = {0};
  char recipient_full[512] = {0};
  uint32_t option = 0;
  while((option=(menu_prompt()-48)))
  {
    printf("option = %d\n", option);
    //Do the thing
    switch(option)
    {
      case 1 :
      print_to_log("User setting recipient", LOG_INFO);
      prompt_input_string("recipient user", recipient_user);
      prompt_input_string("recipient domain", recipient_domain);
      create_recipient_string(recipient_user, recipient_domain, recipient_full);
      break;
      case 2 :
      print_to_log("User composing message", LOG_INFO);
      if(write_message(temp_file)<0)
      {
        perror("write_message");
        printf("Cannot write to %s\n", temp_file);
        print_to_log("composing a message has gone wrong.", LOG_ERR);
      }
      break;
      case 3 :
      print_to_log("User adding attachment", LOG_INFO);
      break;
      case 4 :
      print_to_log("User has sent a message", LOG_INFO);
      break;
      case 5 : //Exit case
      print_to_log("User has terminated Shorebird. Exiting", LOG_INFO);
      exit(0);
      break;
      default :
      break;
    }
  }







}
