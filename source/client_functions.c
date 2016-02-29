#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <assert.h>
#include <syslog.h>

//Include crypto
#include <sodium.h>

#include "client_functions.h"

//Globals
static int init = 0;
static char * local_account;
static int local_account_length = 0;

struct sockaddr_in client_address;

int client_init()
{
	int client_socket = 0;
	if (init == 1)
	{
		return 1;
	}
	if (initlog("cmtp_client")<0)
  {
    perror("Log cannot be opened. Terminating.");
    exit(1);
  }
	if (sodium_init()==-1)
	{
		perror("Sodium cannot init. Exiting");
		print_to_log("Sodium init error. Exiting.", LOG_CRIT);
		exit(1);
	}
	client_socket = socket(AF_INET, SOCK_STREAM, 0);
	client_address.sin_port = htons(CLIENT_PORT);
	client_address.sin_family = AF_INET;
	client_address.sin_addr.s_addr = INADDR_ANY;
	if (bind(client_socket,(struct sockaddr *)&client_address, sizeof(client_address)) < 0)
	{
		perror("Bind() on client_socket has failed\n");
		return -1;
	}
	init = 1;
	return client_socket;
}

/*
Create connection to remote host using local client_socket created in client_init() and using an input sockaddr
ie. take client to init level 2
*/
int connect_remoteV4(uint32_t socket, struct sockaddr_in * remote_sockaddr)
{
	if (client_init() != 1)
	{
		return -1;
	}

	struct sockaddr_in * test_addr = (struct sockaddr_in *) remote_sockaddr;
	test_addr->sin_family = AF_INET;
	test_addr->sin_port = htons(25);

	//struct sockaddr_in* temp_addr = (struct sockaddr_in*)remote_sockaddr;
	//printf("ai_addr hostname ->  %s\n", inet_ntoa(temp_addr->sin_addr));

	if (connect(socket, (const struct sockaddr *) remote_sockaddr, sizeof(*remote_sockaddr)) < 0)
	{
		perror("Client connection error");
	}
	//printf("Connection made\n");

	init = 2;
	return 1;
}

int connect_remoteV6()
{
	//TODO
	return 0;
}

int send_message(uint32_t socket, char * header_buffer, int header_buffer_length, char * message_buffer, int message_buffer_length)
{
	if (init != 2)
	{
		return -1;
	}
	//Should do SMTP like 'HELO'/'ELOH' here when implemented

	char send_buffer[header_buffer_length + message_buffer_length];
	memcpy(&send_buffer[0], header_buffer, header_buffer_length);
	memcpy(&send_buffer[header_buffer_length], message_buffer, message_buffer_length);
	write(socket, send_buffer, sizeof(send_buffer));
	return 0;
}

int build_header(char * recipient, int recipient_length, int crypto_type, int attachment_count, char * return_buffer)
{
	//Concat buffers
	//sender + recipient + crypto type + attachment_count
	int target = 0;
	//Max header size in bytes is 255*4 + 8 = 1028
	char * maximal_header[MAX_HEADER] = {0};
	memcpy(maximal_header[target], local_account, local_account_length);
	target += local_account_length;
	memcpy(maximal_header[target], recipient, recipient_length);
	target += recipient_length;
	memcpy(maximal_header[target], &crypto_type, 4);
	target += 4;
	memcpy(maximal_header[target], &attachment_count, 4);
	target += 4;
	memcpy(return_buffer, maximal_header, target);
	//Return !0 if error
	return 0;
}

int build_message(unsigned char * body, long body_length, unsigned char * recipient_key, char * attachments, long attachments_length,  char * cipher_buffer)
{
	//Step 1: Encipher body and attachments
	char * crypto_buffer = calloc(1, 8 + body_length + attachments_length);
	unsigned char cipherd_body[body_length];
	char * body_buffer = calloc(1, 8+body_length);
	crypto_box_seal(cipherd_body, body, body_length, recipient_key);
	//Step 2: build one memory block
	memcpy(body_buffer, &body_length, 8);
	memcpy(body_buffer + 8, cipherd_body, body_length);
	memcpy(crypto_buffer, body_buffer, 8+body_length);
	free (body_buffer);
	memcpy(crypto_buffer, attachments, attachments_length);
	//Step 3: Return everything as cipher_buffer
	cipher_buffer = crypto_buffer;
	return 1;
}

int encrypt_all_attachmets(int * sizes, unsigned char * * attachments, int num_attachments)
{
	int size = 0;
	//Get recipient_pk from another function. Using recipient_pk = 0 only for testing
	const unsigned char recipient_pk = 0;


	int * offsets = calloc(1, num_attachments * sizeof(int *));
	if (num_attachments == 0)
	{
		return 1;
	}
	for (int i =0; i<num_attachments; i++)
	{
		offsets[i] = size;
		size += sizes[i];
	}
	unsigned char * result = calloc(1, size);
	for (int i = 0; i<num_attachments;i++)
	{
		crypto_box_seal(result+offsets[i], attachments[i], sizes[i], &recipient_pk);
	}
	//Determin true size of attachments. 0 used only for testing
	memcpy(attachments, result, 0);
	return 1;
}

int request_key(uint32_t socket, char * user, char * server, char * keyBuffer)
{
	//Step 1: Construct request message
	//Step 2: Send request message to CMTP server and await reply
	return 0;
}

int login(uint32_t socket, char * server, char * saltedLogin, int saltedLoginLength, char * cipherKeyBuffer)
{
	//TODO
	return 0;
}

int decipher_private_key(char * passWord, char * cipherKeyBuffer, char * clearKeyBuffer)
{
	//TODO
	return 0;
}
