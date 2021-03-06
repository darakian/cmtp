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
  //Trim trailing newline character from user_password
  user_password[strcspn(user_password, "\n")] = 0;
  #ifdef DEBUG
	printf("Attempting to login user %s\n", argv[1]);
  printf("Password = %s\n", user_password);
	#endif /*DEBUG*/

  unsigned char * xzibit = calloc(1, 200);
  unsigned char * private_key_buffer = calloc(1, 64);
  unsigned char * public_key_buffer = calloc(1, 32);
	login(client_socket, argv[1], xzibit);
  if(decipher_xzibit(user_password, strlen(user_password), xzibit, public_key_buffer, private_key_buffer)<0)
  {
    perror("decipher_xzibit error");
    print_to_log("Error deciphering user xzibit", LOG_ERR);
    return -1;
  }

  #ifdef DEBUG
	printf("Login complete for user %s\n", argv[1]);
  print_buffer(private_key_buffer, 64, "Private Key Buffer", 64, 1);
	#endif /*DEBUG*/

  char * temp_file = "/var/tmp/cmtp_compose";
  char recipient_user[256] = {0};
  char recipient_domain[256] = {0};
  char recipient_full[512] = {0};
  char header_buffer[MAX_HEADER] = {0};
  char user_mail_dir[512] = {0};
  char user_mail[1000] = {0};
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
      prompt_input_string("Please type in ", "recipient user", recipient_user, sizeof(recipient_user));
      prompt_input_string("Please type in ", "recipient domain", recipient_domain, sizeof(recipient_domain));
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
        if (read(temp_file_descriptor, temp_file_buffer+i, 1)<0)
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
      #ifdef DEBUG
      //Verify decryption works
      // unsigned char * box_secret_key = calloc(1, 64);
      // unsigned char * box_public_key = calloc(1, 32);
      // crypto_sign_ed25519_pk_to_curve25519(box_public_key,	public_key_buffer);
      // crypto_sign_ed25519_sk_to_curve25519(box_secret_key,	private_key_buffer);
      // char * temp_message_store = calloc(1,100);
      // if (crypto_box_seal_open(temp_message_store, encrypted_file_buffer, encrypted_file_buffer_length, box_public_key, box_secret_key) != 0)
    	// {
      //   perror("crypto_box_seal_open");
    	// 	print_to_log("crypto_box_seal_open failed to decrypt message", LOG_ERR);
    	// }
      // print_buffer(temp_message_store, 20, "temp message", 100, 1);
      #endif /*DEBUG*/
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
      case 5:
      snprintf(user_mail_dir, 512, "%s%c%s", "/var/cmtp/mail", '/', argv[1]);
      select_mail(user_mail_dir, user_mail, 1000);
      display_message(user_mail, private_key_buffer, public_key_buffer, 1);
      break;
      case 6 : //Exit case
      this_is_the_end(client_socket);
      print_to_log("User has terminated Shorebird. Exiting", LOG_INFO);
      exit(0);
      break;
      default :
      break;
    }
  }
}
