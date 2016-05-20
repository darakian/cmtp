//Include guard
#ifndef _clientfunctions_h
#define _clientfunctions_h

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>

#define MAX_HEADER	(255 * 4 + 8)   /* 1028 */
#define CLIENT_PORT 9001

int client_init();

int connect_remoteV4(uint32_t socket, struct sockaddr_in * remote_sockaddr);

int login(uint32_t socket, char * username, unsigned char * xzibit_buffer);

int32_t send_message(uint32_t socket, char * header_buffer, uint32_t header_buffer_length, unsigned char * message_buffer, uint32_t message_buffer_length);

int write_message(char * temp_file);

int32_t set_local_params(char * local_user, char * local_domain);

uint32_t create_recipient_string(char * user, char * domain, char * full);

int32_t build_header(char * recipient, uint32_t recipient_length, uint32_t version, uint32_t attachment_count, uint64_t log_length, uint64_t message_length, char * return_buffer);

int32_t build_message(unsigned char * body, long body_length, unsigned char * recipient_key, char * attachments, long attachments_length,  unsigned char * cipher_buffer);

int encrypt_all_attachmets(int * sizes, unsigned char * * attachments, int num_attachments);

int32_t request_server_key(uint32_t socket, unsigned char * key_buffer);

int32_t request_user_key(uint32_t socket, char * user, char * server, unsigned char * key_buffer);

int32_t decipher_xzibit(char * password, uint32_t password_length, unsigned char * xzibit_buffer, unsigned char * private_key_buffer);

int32_t interperate_server_response(uint32_t socket);

uint32_t menu_prompt();

int32_t clear_socket(uint32_t socket);

int32_t this_is_the_end(uint32_t my_only_friend);

#endif
