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

int login(uint32_t socket, char * username, char * key_buffer);

int send_message(uint32_t socket, char * header_buffer, int header_buffer_length, char * message_buffer, int message_buffer_length);

int write_message(char * temp_file);

uint32_t prompt_input_string(char * descriptor, char * storage);

uint32_t create_recipient_string(char * user, char * domain, char * full);

int32_t build_header(char * recipient, uint32_t recipient_length, uint32_t version, uint32_t attachment_count, uint64_t log_length, char * return_buffer);

int build_message(unsigned char * body, long body_length, unsigned char * recipient_key, char * attachments, long attachments_length,  char * cipher_buffer);

int encrypt_all_attachmets(int * sizes, unsigned char * * attachments, int num_attachments);

int32_t request_key(uint32_t socket, char * user, char * server, unsigned char * key_buffer);

int32_t decipher_private_key(char * password, unsigned char * cipher_key_buffer, unsigned char * clear_key_buffer);

uint32_t menu_prompt();


#endif
