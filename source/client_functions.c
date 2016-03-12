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
#include <sys/wait.h>
#include <ctype.h>

//Include crypto
#include <sodium.h>

#include "client_functions.h"
#include "cmtp_common.h"

//Globals
static int init = 0;
static char * local_account;
static int local_account_length = 0;
const char cmtp_command_OHAI[] = {"OHAI"};
const char cmtp_command_MAIL[] = {"MAIL"};
const char cmtp_command_HELP[] = {"HELP"};
const char cmtp_command_NOOP[] = {"NOOP"};
const char cmtp_command_LOGIN[] = {"LOGIN"};
const char cmtp_command_OBAI[] = {"OBAI"};
const char cmtp_command_KEYREQUEST[] = {"KEYREQUEST"};
unsigned char server_public_key[crypto_sign_ed25519_PUBLICKEYBYTES] = {0};

struct sockaddr_in client_address;

int client_init()
{
	int client_socket = 0;
	if (init == 1)
	{
		return -1;
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
	struct sockaddr_in * test_addr = (struct sockaddr_in *) remote_sockaddr;
	test_addr->sin_family = AF_INET;
	test_addr->sin_port = htons(25);

	//struct sockaddr_in* temp_addr = (struct sockaddr_in*)remote_sockaddr;
	//printf("ai_addr hostname ->  %s\n", inet_ntoa(temp_addr->sin_addr));

	if (connect(socket, (const struct sockaddr *) remote_sockaddr, sizeof(*remote_sockaddr)) < 0)
	{
		perror("Client connection error");
	}
	if (write(socket,"OHAI\0",5)<0)
	{
		perror("write");
		print_to_log("Cannot write to connected socket.", LOG_EMERG);
		return -1;
	}
	//Should read for a CMTP response here in order to verify that the connection is a CMTP connection.
	return 1;
}

int connect_remoteV6()
{
	//TODO
	return 0;
}

int login(uint32_t socket, char * username, char * key_buffer)
{
	char login_buffer[6+255] = {0};
	char reception_buffer[4+32+1+16+1] = {0};
	uint32_t login_buffer_length = snprintf(login_buffer, sizeof(login_buffer), "%s%s", "LOGIN\0", username);
	if (write(socket, login_buffer, login_buffer_length)<0)
	{
		perror("write");
		print_to_log("Error writing login request to socket", LOG_ERR);
		return -1;
	}
	if (read(socket, reception_buffer, sizeof(reception_buffer))<0)
	{
		perror("read");
		print_to_log("Error reading from socket after login attempt.", LOG_ERR);
		return -1;
	}
	//Else we have what we want.
	//Need to lock down LOGIN documentation before proceeding
	return 0;
}

int send_message(uint32_t socket, char * header_buffer, int header_buffer_length, char * message_buffer, int message_buffer_length)
{
	if (init != 1)
	{
		perror("client init has not run. Cannot send mail.");
		print_to_log("client init has not run. Cannot send mail.", LOG_ERR);
		return -1;
	}
	//Should do SMTP like 'HELO'/'ELOH' here when implemented
	char send_buffer[header_buffer_length + message_buffer_length];
	memcpy(send_buffer, header_buffer, header_buffer_length);
	memcpy(send_buffer+header_buffer_length, message_buffer, message_buffer_length);
	if (write(socket, send_buffer, sizeof(send_buffer))<0)
	{
		perror("Write");
		print_to_log("Sending message failed.", LOG_ERR);
		return -1;
	}
	return 0;
}

int32_t write_message(char * temp_file)
{
	printf("temp_file = %s\n", temp_file);
	pid_t child_pid = -1;
	int32_t wait_result = 0;
	if(child_pid = fork())
  {
		//Parent
		int32_t status = -1;
		wait_result = waitpid(child_pid, &status, 0);
		return 0;
	}
	else
	{
		//Child
		execlp("vi", "vi",  temp_file, NULL);
	}
	return -1;
}

int32_t build_header(char * recipient, uint32_t recipient_length, uint32_t crypto_type, uint32_t attachment_count, char * return_buffer)
{
	//Concat buffers
	//sender + recipient + crypto type + attachment_count
	int32_t target = 0;
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

int32_t request_key(uint32_t socket, char * user, char * server, unsigned char * key_buffer)
{
	uint32_t version = 0;
	uint32_t request_buffer_length = strlen(user) + strlen(server)+sizeof(cmtp_command_KEYREQUEST)+3;
	unsigned char reception_buffer[4+crypto_sign_ed25519_SECRETKEYBYTES+crypto_sign_BYTES] = {0};
	char request_buffer[(2*255)+sizeof(cmtp_command_KEYREQUEST)+1] = {0};
	if (snprintf(request_buffer, sizeof(request_buffer), "%s%c%s%c%s%c", cmtp_command_KEYREQUEST, '\0', user, '\0',server, '\0')<0)
	{
		perror("snprintf");
		print_to_log("Cannot construct key request buffer.", LOG_ERR);
		return -1;
	}
	//printf("%d\n", request_buffer_length);
	//printf("%s\n", request_buffer);
	if (write(socket, request_buffer, request_buffer_length)<0)
	{
		perror("write");
		print_to_log("Cannot send key request.", LOG_ERR);
		return -1;
	}
	if (read(socket, reception_buffer, sizeof(reception_buffer))<0)
	{
		perror("read");
		print_to_log("Cannot read reply from key request.", LOG_ERR);
	}
	//Verify and copy result to key_buffer
	version = ntohl(*(uint32_t *)reception_buffer);
	//Only version 1 is supported here.
	if (version!=1)
	{
		perror("Key version unsupported");
		print_to_log("Unsupported key type recived", LOG_ERR);
		return -1;
	}
	memcpy(key_buffer, reception_buffer+4, crypto_sign_ed25519_SECRETKEYBYTES);
	//check signature
	if (crypto_sign_verify_detached(reception_buffer+4+crypto_sign_ed25519_SECRETKEYBYTES, reception_buffer+4, crypto_sign_ed25519_SECRETKEYBYTES, server_public_key) != 0)
	{
    perror("crypto_sign_verify_detached");
		print_to_log("Signature is not valid for delieverd key", LOG_ERR);
		memset(key_buffer, 0, crypto_sign_ed25519_SECRETKEYBYTES);
		return -1;
	}
	return 0;
}

int32_t decipher_private_key(char * password, unsigned char * cipher_key_buffer, unsigned char * clear_key_buffer)
{
	//TODO
	return 0;
}

uint32_t menu_prompt()
{
	char option[20] = {0};
	printf("Welcome to Shorebird version <1\n");
	printf("**********MENU**********\n");
	printf("1: Set Recipient\n");
	printf("2: Compose message\n");
	printf("3: Add an attachment (NOT YET WORKING)\n");
	printf("4: Send message\n");
	printf("5: Quit\n");
	printf("************************\n");
	if (fgets(option, sizeof(option), stdin)==NULL)
  {
    perror("fgets");
  }
	//printf("read %x\n", option[0]);
	return (uint32_t)option[0];
}

uint32_t create_recipient_string(char * user, char * domain, char * full)
{
	snprintf(full, sizeof(user)+sizeof(domain), "%s%d%s%d", user, '\0', domain, '\0');
	return sizeof(user)+sizeof(domain);
}

//Gets input from user. Removes trailing newline character.
uint32_t prompt_input_string(char * descriptor, char * storage)
{
	char * welcome = "Please type in ";
	char input[256] = {0};
	printf("%s%s\n", welcome, descriptor);
	if (fgets(input, sizeof(input), stdin)==NULL)
  {
    perror("fgets");
  }
	memcpy(storage, input, strlen(input)-1);
	return sizeof(storage);
}
