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

int connect_remoteV4(struct sockaddr * remote_sockaddr);

int send_message(char * header_buffer, int header_buffer_length, char * message_buffer, int message_buffer_length);

int build_header(char * recipient, int recipient_length, int crypto_type, int attachment_count, char * return_buffer);

int build_message(unsigned char * body, long body_length, unsigned char * recipient_key, char * attachments, long attachments_length,  char * cipher_buffer);

int encrypt_all_attachmets(int * sizes, unsigned char * * attachments, int num_attachments);

int request_key(char * user, char * server, char * keyBuffer);

int login(char * server, char * saltedLogin, int saltedLoginLength, char * cipherKeyBuffer);

int decipher_private_key(char * passWord, char * cipherKeyBuffer, char * clearKeyBuffer);


#endif
