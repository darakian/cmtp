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
  unsigned char user_key_buffer[crypto_sign_ed25519_SECRETKEYBYTES] = {0};
  unsigned char recipient_key_buffer[crypto_sign_ed25519_SECRETKEYBYTES] = {0};
  unsigned char server_public_key[crypto_sign_ed25519_SECRETKEYBYTES] = {0};
  char user_key_path[400] = {0};
  char base64_username[341] = {0};
  char user_password[255] = {0};


  if ((client_socket = client_init())<0)
  {
    perror("client init");
    print_to_log("Client init failed. Terminating", LOG_CRIT);
    exit(1);
  }

  if (set_local_params(argv[1], argv[2])<0)
  {
    // printf("user = %s\n", argv[1]);
    // printf("domain = %s\n", argv[2]);
    perror("set_local_params");
    print_to_log("Cannot set local parameters", LOG_ERR);
    exit(1);
  }
  struct sockaddr_in post_desktop;

  //int32_t server_length =  resolve_server("edo.im", (struct sockaddr_storage *)&post_desktop);
  post_desktop.sin_addr.s_addr = inet_addr("128.171.10.79");
  post_desktop.sin_family = AF_INET;
  post_desktop.sin_port = htons(9001);
  if (connect(client_socket, (struct sockaddr *)&post_desktop, sizeof(post_desktop))<0)
  {
    perror("connect");
    print_to_log("cannot connect to cmpt server", LOG_EMERG);
    exit(1);
  }
  clear_socket(client_socket);
  #ifdef DEBUG
  printf("Using %s as cmtp server\n", inet_ntoa(post_desktop.sin_addr));
  #endif /*DEBUG*/
  request_server_key(client_socket, server_public_key);

  printf("Password Please:\n");
  if (fgets(user_password, sizeof(user_password), stdin)==NULL)
  {
    perror("fgets");
  }
  //Exit if username exceeds CMTP limit
  if ((strlen(argv[1])>255)||(strlen(user_password)<=0))
  {
    perror("Username too long or password too short");
    print_to_log("Username too long or password too short. Exiting.", LOG_CRIT);
    exit(1);
  }
  //Base64-ify the username
  base64_encode(argv[1], strlen(argv[1]), base64_username, sizeof(base64_username), (char *)filesystem_safe_base64_string, 64);
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
  char header_buffer[MAX_HEADER] = {0};
  int32_t header_buffer_length = 0;
  uint32_t recipient_length = 0;
  uint32_t option = 0;
  while((option=(menu_prompt()-48)))
  {
    #ifdef DEBUG
    printf("option = %d\n", option);
    #endif /*DEBUG*/
    //Do the thing
    switch(option)
    {
      case 1 :
      print_to_log("User setting recipient", LOG_INFO);
      prompt_input_string("recipient user", recipient_user);
      prompt_input_string("recipient domain", recipient_domain);
      recipient_length = create_recipient_string(recipient_user, recipient_domain, recipient_full);
      request_user_key(client_socket, recipient_user, recipient_domain, recipient_key_buffer);
      printf("Ending recipient setting\n");
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
      if ((strlen(recipient_full)==0)||(access(temp_file, R_OK)<0))
      {
        printf("Please fill in a recipient and write a message");
        break;
      }
      //Read file back in and get a char * to it
      struct stat temp_file_stats;
      stat(temp_file, &temp_file_stats);
      uint32_t temp_file_size = temp_file_stats.st_size;
      int32_t encrypted_file_buffer_length = 0;
      unsigned char * temp_file_buffer = calloc(1, temp_file_size);
      unsigned char * encrypted_file_buffer = calloc(1, temp_file_size+crypto_box_SEALBYTES);
      int32_t temp_file_descriptor = 0;
      temp_file_descriptor = open(temp_file, O_RDONLY);
      #ifdef DEBUG
      printf("Before read temp_file_descriptor\n");
      #endif /*DEBUG*/
      for (uint32_t i = 0; i<=temp_file_size; i++)
      {
        if (read(temp_file_descriptor, temp_file_buffer, 1)<0)
        {
          perror("read");
          print_to_log("Error reading in users message", LOG_ERR);
        }
      }
      if (close(temp_file_descriptor)<0)
      {
        perror("close");
        print_to_log("Error closing temp_file_descriptor", LOG_ERR);
      }
      #ifdef DEBUG
      printf("Before build message\n");
      #endif /*DEBUG*/
      //Encrypt message
      if ((encrypted_file_buffer_length = build_message(temp_file_buffer, temp_file_size, recipient_key_buffer, NULL, 0,  encrypted_file_buffer))<0)
      {
        perror("build_message");
        print_to_log("Error building encrypred message", LOG_ERR);
      }
      //Build header
      //build_header(char * recipient, uint32_t recipient_length, uint32_t crypto_type, uint32_t attachment_count, char * return_buffer)
      printf("Attempting to build header for %s\n", recipient_full);
      if ((header_buffer_length = build_header(recipient_full, recipient_length, 1, 0, 0, encrypted_file_buffer_length, header_buffer))<0)
      {
        perror("build_header");
        print_to_log("Failed to build message header", LOG_ERR);
      }
      printf("Header built!\n");
      printf("header length = %d\n", header_buffer_length);
      //Send mail
      #ifdef DEBUG
      printf("Sending message with header size = %d, Message body size = %d\n", header_buffer_length, encrypted_file_buffer_length);
      #endif /*DEBUG*/
      if(send_message(client_socket, header_buffer, header_buffer_length, encrypted_file_buffer, encrypted_file_buffer_length)<0)
      {
        perror("send_message");
        print_to_log("Failed to send message", LOG_ERR);
        break;
      }
      print_to_log("User has sent a message", LOG_INFO);
      break;
      case 5 : //Exit case
      this_is_the_end(client_socket);
      print_to_log("User has terminated Shorebird. Exiting", LOG_INFO);
      exit(0);
      break;
      default :
      break;
    }
  }
}
