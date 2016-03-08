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

int32_t build_header(char * recipient, uint32_t recipient_length, uint32_t crypto_type, uint32_t attachment_count, char * return_buffer);

int build_message(unsigned char * body, long body_length, unsigned char * recipient_key, char * attachments, long attachments_length,  char * cipher_buffer);

int encrypt_all_attachmets(int * sizes, unsigned char * * attachments, int num_attachments);

int request_key(uint32_t socket, char * user, char * server, char * keyBuffer);

int decipher_private_key(char * passWord, char * cipherKeyBuffer, char * clearKeyBuffer);

uint32_t menu_prompt();


#endif
