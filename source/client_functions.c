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
#include <endian.h>
#include <dirent.h>

//Include crypto
#include <sodium.h>

#include "client_functions.h"
#include "cmtp_common.h"

#define KEY_LEN 32

//Globals
static int init = 0;
const char cmtp_command_OHAI[] = {"OHAI"};
const char cmtp_command_MAIL[] = {"MAIL"};
const char cmtp_command_HELP[] = {"HELP"};
const char cmtp_command_NOOP[] = {"NOOP"};
const char cmtp_command_LOGIN[] = {"LOGIN"};
const char cmtp_command_OBAI[] = {"OBAI"};
const char cmtp_command_KEYREQUEST[] = {"KEYREQUEST"};
unsigned char server_public_key[crypto_sign_ed25519_PUBLICKEYBYTES] = {0};
static char local_account[256] = {0};
static uint32_t local_account_length = 0;
static char local_domain[256] = {0};
static uint32_t local_domain_length = 0;
const char termination_char = '\0';

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
	// client_address.sin_port = htons(CLIENT_PORT);
	// client_address.sin_family = AF_INET;
	// client_address.sin_addr.s_addr = INADDR_ANY;
	// if (bind(client_socket,(struct sockaddr *)&client_address, sizeof(client_address)) < 0)
	// {
	// 	perror("Bind() on client_socket has failed\n");
	// 	return -1;
	// }
	init = 1;
	return client_socket;
}

int32_t set_local_params(char * local_user, char * local_server)
{
	if ((strlen(local_user)<=0)||(strlen(local_server)<=0)||(strlen(local_user)>255)||(strlen(local_server)>255))
	{
		perror("strlen");
		print_to_log("Invalid call to set_local_params", LOG_ERR);
		return -1;
	}
	memcpy(local_account, local_user, strlen(local_user));
	local_account_length = strlen(local_user)+1;
	memcpy(local_domain, local_server, strlen(local_server));
	local_domain_length = strlen(local_server)+1;
	print_to_log("Local user and domain set", LOG_INFO);
	return 0;
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

int login(uint32_t socket, char * username, unsigned char * xzibit_buffer)
{
	char login_buffer[6+255] = {0};
	unsigned char reception_buffer[500] = {0};
	uint32_t xzibit_version = 0;
	uint64_t xzibit_length = 0;
	uint32_t login_buffer_length = snprintf(login_buffer, sizeof(login_buffer), "%s%c%s%c", "LOGIN", '\0', username, '\0');
	if (write(socket, login_buffer, login_buffer_length)<0)
	{
		perror("write");
		print_to_log("Error writing login request to socket", LOG_ERR);
		return -1;
	}
	//read version
  if (read_n_bytes(socket, reception_buffer, 4)<4)
	{
		perror("read_n_bytes");
		print_to_log("Failed to read in login", LOG_ERR);
		return -1;
	}
	memcpy(&xzibit_version, reception_buffer, 4);
	xzibit_version = be32toh(xzibit_version);
	#ifdef DEBUG
	printf("Attempting check version = %d\n", xzibit_version);
	//print_buffer(reception_buffer, 4, NULL, sizeof(reception_buffer), 1);
	#endif /**/
	if (xzibit_version!=1)
	{
		perror("Incorrect xzibit version");
		print_to_log("Incorrect xzibit", LOG_ERR);
		return -1;
	}
	#ifdef DEBUG
	printf("Attempting to read salt\n");
	#endif /**/
	//read salt
	if (read_n_bytes(socket, reception_buffer+4, 32)<32)
	{
		perror("Incorrect read amount");
		print_to_log("Failed to read xzibit salt", LOG_ERR);
		return -1;
	}
	#ifdef DEBUG
	printf("Attempting to read xzibit length\n");
	#endif /**/
	//read xzibit length
	if (read_n_bytes(socket, reception_buffer+4+32, 8)<8)
	{
		perror("Incorrect read amount");
		print_to_log("Failed to read xzibit length", LOG_ERR);
		return -1;
	}
	memcpy(&xzibit_length, reception_buffer+4+32, 8);
	xzibit_length = be64toh(xzibit_length);
	#ifdef DEBUG
	printf("Attempting to xzibit of length = %ld\n", xzibit_length);
	#endif /*DEBUG*/
	//Read xzibit
	if (read_n_bytes(socket, reception_buffer+4+32+8, xzibit_length)<xzibit_length)
	{
		perror("Incorrect read amount");
		print_to_log("Failed to read xzibit", LOG_ERR);
		return -1;
	}
	//Read signature
	if (read_n_bytes(socket, reception_buffer+4+32+8+xzibit_length, 64)<64)
	{
		perror("Incorrect read amount");
		print_to_log("Failed to read signature", LOG_ERR);
		return -1;
	}
	//Verify xzibit
	if (crypto_sign_verify_detached(reception_buffer+4+32+8+xzibit_length, reception_buffer, xzibit_length+4+32+8, server_public_key)!=0)
	{
		perror("Invalid signature for error message.");
		print_to_log("Error message recived in response to keyrequest. Cannot verify message. Bad joo joo time is here", LOG_ERR);
		return -1;
	}
	//Return everything but the signature
	memcpy(xzibit_buffer, reception_buffer, 4+32+8+xzibit_length);
	//Else we have what we want.
	return 4+32+8+xzibit_length;
}

int32_t send_message(uint32_t socket, char * header_buffer, uint32_t header_buffer_length, unsigned char * message_buffer, uint32_t message_buffer_length)
{
	//Send MAIL\0 command
	#ifdef DEBUG
	printf("send_message called with header of size %d and message of size %d\n", header_buffer_length, message_buffer_length);
	#endif /*DEBUG*/
	if (write(socket, cmtp_command_MAIL, sizeof(cmtp_command_MAIL))<0)
	{
		perror("Write");
		print_to_log("Sending mail command failed.", LOG_ERR);
		return -1;
	}
	if (write(socket, header_buffer, header_buffer_length)<0)
	{
		perror("Write");
		print_to_log("Sending message failed.", LOG_ERR);
		return -1;
	}
	if (write(socket, message_buffer, message_buffer_length)<0)
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
	if((child_pid = fork()))
  {
		//Parent
		int32_t status = -1;
		if(waitpid(child_pid, &status, 0)<0)
		{
			perror("waitpid");
			print_to_log("Error waiting on child in fork", LOG_ERR);
		}

		return 0;
	}
	else
	{
		//Child
		execlp("vi", "vi",  temp_file, NULL);
	}
	return -1;
}

int32_t build_header(char * recipient, uint32_t recipient_length, uint32_t version, uint32_t attachment_count, uint64_t log_length, uint64_t message_length, char * return_buffer)
{
	#ifdef DEBUG
	printf("Building message header destined for: \n");
	for (uint32_t i =0; i<recipient_length; i++)
	{
		printf("%c / %x\n", recipient[i], recipient[i]);
	}
	printf("Variables are: recipient_length = %d, attachment_count = %d, log_length = %ld\n", recipient_length, attachment_count, log_length);
	#endif /*DEBUG*/
	//Builds the CMTP message header
	uint32_t target = 0;
	uint32_t net_version = htobe32(version);
	uint32_t net_attachment_count = htobe32(attachment_count);
	uint64_t net_log_length = htobe64(log_length);
	uint64_t net_message_length = htobe64(message_length);
	char maximal_header[MAX_HEADER] = {0};
	memcpy(maximal_header+target, &net_version, 4);
	target += 4;
	memcpy(maximal_header+target, &net_attachment_count, 4);
	target += 4;
	memcpy(maximal_header+target, &net_log_length, 8);
	target += 8;
	memcpy(maximal_header+target, &net_message_length, 8);
	target+=8;
	memcpy(maximal_header+target, recipient, recipient_length);
	target += recipient_length;
	memcpy(maximal_header+target, local_account, local_account_length);
	target += local_account_length;
	memcpy(maximal_header+target, local_domain, local_domain_length);
	target += local_domain_length;
	memcpy(return_buffer, maximal_header, target);
	//Return -1 if error
	#ifdef DEBUG
	printf("Complete buffer contents: \n");
	for (uint32_t i =0; i<target; i++)
	{
		printf("%c / %x\n", maximal_header[i], maximal_header[i]);
	}
	printf("target = %d\n", target);
	#endif /*DEBUG*/
	return target;
}

int32_t build_message(unsigned char * body, long body_length, unsigned char * recipient_key, char * attachments, long attachments_length,  unsigned char * cipher_buffer)
{
	//Step 1: Encipher body and attachments
	#ifdef DEBUG
	printf("Building message with body_length = %ld and attachments_length = %ld\n", body_length, attachments_length);
	#endif /*DEBUG*/
	uint64_t cipher_text_length = body_length+crypto_box_SEALBYTES;
	char * crypto_buffer = calloc(1, cipher_text_length + attachments_length);
	unsigned char ciphered_body[cipher_text_length];
	memset(ciphered_body, 0, cipher_text_length);
	//memset ciphered_body to zero here
	crypto_box_seal(ciphered_body, body, body_length, recipient_key);
	//Step 2: copy encrypted contents to the buffer working
	memcpy(crypto_buffer, ciphered_body, cipher_text_length);
	memcpy(crypto_buffer+cipher_text_length, attachments, attachments_length);
	//Step 3: Return everything as cipher_buffer
	#ifdef DEBUG
	printf("Messsage size is %ld\n", (cipher_text_length+attachments_length));
	#endif /*DEBUG*/
	memcpy(cipher_buffer, crypto_buffer, (cipher_text_length+attachments_length));
	free(crypto_buffer);
	// print_buffer(cipher_buffer, cipher_text_length, NULL, sizeof(cipher_buffer), 1);
	return (cipher_text_length+attachments_length);
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

int32_t request_server_key(uint32_t socket, unsigned char * key_buffer)
{
	return request_user_key(socket, "", "", key_buffer);
}

int32_t request_user_key(uint32_t socket, char * user, char * domain, unsigned char * key_buffer)
{
	#ifdef DEBUG
	printf("Begining keyrequest for user=%s, domain=%s\n", user, domain);
	#endif /*DEBUG*/
	uint32_t version = 0;
	int32_t read_length = 0;
	printf("strlen = %ld\n", strlen(user));
	uint32_t request_buffer_length = 0;
	unsigned char reception_buffer[4+crypto_sign_ed25519_SECRETKEYBYTES+crypto_sign_BYTES] = {0};
	char request_buffer[(2*255)+sizeof(cmtp_command_KEYREQUEST)+1] = {0};
	request_buffer_length = strlen(user) + strlen(domain)+sizeof(cmtp_command_KEYREQUEST)+3;
	if ((strlen(user)==0)&&(strlen(domain)==0))
	{
		//Server keyrequest case
		if (snprintf(request_buffer, sizeof(request_buffer), "%s%c%c", cmtp_command_KEYREQUEST, '\0', '\0')<0)
		{
			perror("snprintf");
			print_to_log("Cannot construct key request buffer.", LOG_ERR);
			return -1;
		}
		request_buffer_length = sizeof(cmtp_command_KEYREQUEST)+1;
		if (write(socket, request_buffer, request_buffer_length)<0)
		{
			perror("write");
			print_to_log("Cannot send key request for server key.", LOG_ERR);
			return -1;
		}
		if ((read_length=read(socket, reception_buffer, sizeof(reception_buffer)))<0)
		{
			perror("read");
			print_to_log("Cannot read reply from key request.", LOG_ERR);
		}
		#ifdef DEBUG
		printf("Read %d bytes as response to server keyrequest\n", read_length);
		#endif /*DEBUG*/
		//Verify server key
		// print_buffer(reception_buffer+4, 32, "Server public key: ", 32, 1);
		// print_buffer(reception_buffer+4+crypto_sign_ed25519_PUBLICKEYBYTES+sizeof(termination_char), 64, "Server public key signature: ", 64, 1);
		int32_t temp_int = 0;
		if ((temp_int = crypto_sign_verify_detached(reception_buffer+4+crypto_sign_ed25519_PUBLICKEYBYTES+sizeof(termination_char), reception_buffer+4, crypto_sign_ed25519_PUBLICKEYBYTES, reception_buffer+4))!=0)
		{
			printf("Sign return value = %d\n", temp_int);
			perror("Invalid signature for server public key.");
			print_to_log("Invalid signature for server public key.", LOG_ERR);
			return -1;
		}
		memcpy(server_public_key, reception_buffer+4, sizeof(server_public_key));
		return 0;
	}

	//Invalid request case
	if ((strlen(user)==0)&&(strlen(domain)!=0))
	{
		print_to_log("Invalid keyrequest with null user and non-null domain", LOG_INFO);
		return -1;
	}

	//Request user from home domain
	if ((strlen(user)!=0)&&(strlen(domain)==0))
	{
		if (snprintf(request_buffer, sizeof(request_buffer), "%s%c%s%c%c", cmtp_command_KEYREQUEST, '\0', user, '\0', '\0')<0)
		{
			perror("snprintf");
			print_to_log("Cannot construct key request buffer.", LOG_ERR);
			return -1;
		}
		if (write(socket, request_buffer, request_buffer_length)<0)
		{
			perror("write");
			print_to_log("Cannot send key request.", LOG_ERR);
			return -1;
		}
		if ((read_length=read(socket, reception_buffer, sizeof(reception_buffer)))<0)
		{
			perror("read");
			print_to_log("Cannot read reply from key request.", LOG_ERR);
		}
	}

	//Default keyrequest. Still sends to home server.
	if (snprintf(request_buffer, sizeof(request_buffer), "%s%c%s%c%s%c", cmtp_command_KEYREQUEST, '\0', user, '\0',domain, '\0')<0)
	{
		perror("snprintf");
		print_to_log("Cannot construct key request buffer.", LOG_ERR);
		return -1;
	}
	if (write(socket, request_buffer, request_buffer_length)<0)
	{
		perror("write");
		print_to_log("Cannot send key request.", LOG_ERR);
		return -1;
	}
	//Sleep is here to prevent reading only 4 bytes in the following read
	if ((read_length=read(socket, reception_buffer, sizeof(reception_buffer)))<0)
	{
		perror("read");
		print_to_log("Cannot read reply from key request.", LOG_ERR);
	}
	#ifdef DEBUG
	printf("Read in %d bytes\n", read_length);
	#endif /*DEBUG*/


	//Verify and copy result to key_buffer
	version = be32toh(*(uint32_t *)reception_buffer);
	#ifdef DEBUG
	printf("Key version = %d\n", version);
	#endif /*DEBUG*/
	if (version==0)
	{
		//error message case. Verify signature and take action.
		#ifdef DEBUG
		// print_buffer (server_public_key, 32, "Server public key: ", 32, 1);
		// print_buffer (reception_buffer+4, 32, "User public key: ", 32, 1);
		#endif /*DEBUG*/
		if (crypto_sign_verify_detached(reception_buffer+4+crypto_sign_ed25519_PUBLICKEYBYTES+sizeof(termination_char), reception_buffer+4, crypto_sign_ed25519_PUBLICKEYBYTES, server_public_key)!=0)
		{
			perror("Invalid signature for error message.");
			print_to_log("Error message recived in response to keyrequest. Cannot verify message. Bad joo joo time is here", LOG_ERR);
			return -1;
		}
	}
	if (version==1)
	{
		#ifdef DEBUG
		// print_buffer (server_public_key, 32, "Server public key: ", 32, 1);
		// print_buffer (reception_buffer+4, 32, "User public key: ", 32, 1);
		#endif /*DEBUG*/
		//check signature
		if (crypto_sign_verify_detached(reception_buffer+4+crypto_sign_ed25519_PUBLICKEYBYTES+sizeof(termination_char), reception_buffer+4, crypto_sign_ed25519_PUBLICKEYBYTES, server_public_key) != 0)
		{
	    perror("crypto_sign_verify_detached");
			print_to_log("Signature is not valid for delieverd key", LOG_ERR);
			return -1;
		}
		memcpy(key_buffer, reception_buffer+4, crypto_sign_ed25519_PUBLICKEYBYTES);
	}
	else if (version>1)
	{
		#ifdef DEBUG
		for (uint32_t i = 0; i<32; i++)
		{
			printf("%x", *reception_buffer+4+i);
		}
		printf("\n");
		#endif /*DEBUG*/
		//Invalid key case. Seriously I haven't even gotten version 1 working yet!!!
		perror("Key version unsupported");
		printf("Key version = %d\n", version);
		print_to_log("Unsupported key type recived", LOG_ERR);
		return -1;
	}
	return 0;
}

/*
* decipher_xzibit takes the entire xzibit as parameter two (version, salt, everything) and fills in private_key_buffer with the enciphered private key
*/
int32_t decipher_xzibit(char * password, uint32_t password_length, unsigned char * xzibit_buffer, unsigned char * public_key_buffer, unsigned char * private_key_buffer)
{
	if(sodium_init()==-1)
	{
		perror("Cannot use crypto");
		print_to_log("Sodium init failed. Cannot decrypt xzibit_buffer", LOG_ERR);
		return -1;
	}
	#ifdef DEBUG
	printf("Post sodium init\n");
	#endif /*DEBUG*/
	unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
	unsigned char salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
	unsigned char hash[KEY_LEN] = {0};
	uint64_t ciphertext_len = 0;
	memcpy(nonce, xzibit_buffer+4, sizeof(nonce));
	memcpy(salt, xzibit_buffer+4, sizeof(salt));
	memcpy(&ciphertext_len, xzibit_buffer+36, 8);
	ciphertext_len = be64toh(ciphertext_len);
	unsigned char plaintext[512];
	uint64_t plaintext_len = 0;
	#ifdef DEBUG
	printf("password_length = %d\n", password_length);
	print_buffer(nonce, sizeof(nonce), "nonce", 12, 1);
	print_buffer(salt, sizeof(salt), "salt", 32, 1);
	print_buffer(xzibit_buffer+44, ciphertext_len, "ciphertext", 256, 1);
	#endif /*DEBUG*/
	//Hash password
	if (crypto_pwhash_scryptsalsa208sha256(hash, sizeof(hash), password, password_length, salt, crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0)
  {
    perror("crypto_pwhash_scryptsalsa208sha256");
		print_to_log("Cannot hash user password.", LOG_ERR);
		return -1;
  }
	int i = 0;
	#ifdef DEBUG
	printf("Post password hash\n");
	print_buffer(hash, sizeof(hash), "hash", 256, 1);
	printf("nonce size = %d\n", crypto_aead_aes256gcm_NPUBBYTES);
	printf("ciphertext_len = %ld, crypto_aead_aes256gcm_ABYTES = %d\n", ciphertext_len, crypto_aead_aes256gcm_ABYTES);
	#endif /*DEBUG*/
	if ((ciphertext_len < crypto_aead_aes256gcm_ABYTES) || ((i=crypto_aead_aes256gcm_decrypt(plaintext, &plaintext_len, NULL, xzibit_buffer+44, ciphertext_len, NULL, 0, nonce, hash)) != 0))
	{
		printf("AES return value = %d\n", i);
		print_buffer(plaintext, plaintext_len, "plaintext", 256, 1);
    perror("xzibit_buffer decrypt error");
		print_to_log("Xzibit decrypt error", LOG_ERR);
		return -1;
	}
	#ifdef DEBUG
	printf("Post AES decrypt\n");
	#endif /*DEBUG*/
	//Copy key and return
	memcpy(public_key_buffer, plaintext, 32);
	memcpy(private_key_buffer, plaintext+32, 64);
	#ifdef DEBUG
	printf("Post memcpy. Returning\n");
	#endif /*DEBUG*/
	return 0;
}

uint32_t menu_prompt()
{
	fseek(stdin,0,SEEK_END);
	char option[20] = {0};
	printf("Welcome to Shorebird version <1\n");
	printf("**********MENU**********\n");
	printf("1: Set Recipient\n");
	printf("2: Compose message\n");
	printf("3: Add an attachment (NOT YET WORKING)\n");
	printf("4: Send message\n");
	printf("5: Read message\n");
	printf("6: Quit\n");
	printf("************************\n");
	if (fgets(option, sizeof(option), stdin)==NULL)
  {
    perror("fgets");
  }
	fseek(stdin,0,SEEK_END);
	#ifdef DEBUG
	printf("Menu prompt thinks option = %d\n", option[0]);
	#endif /*DEBUG*/
	return (uint32_t)option[0];
}

uint32_t create_recipient_string(char * user, char * domain, char * full)
{
	snprintf(full, strlen(user)+strlen(domain)+2, "%s%c%s", user, '\0', domain);
	return strlen(user)+strlen(domain)+2;
}

int32_t interperate_server_response(uint32_t socket)
{
	char server_response[255] = {0};
	uint32_t i = 4;
	//Read version
	if (read(socket, server_response, 4)<0)
	{
		perror("read in interperate_server_response");
		print_to_log("Failed to read from socket during interperate_server_response function", LOG_ERR);
	}
	//Read until first terminator
	do {
		if (read(socket, server_response+i, 1)<0)
		{
			perror("read in interperate_server_response");
			print_to_log("Failed to read from socket during interperate_server_response function", LOG_ERR);
		}
		i++;
	} while((i<sizeof(server_response))&&(server_response[i-1]!=termination_char));
	//Read until second terminator
	do {
		if (read(socket, server_response+i, 1)<0)
		{
			perror("read in interperate_server_response");
			print_to_log("Failed to read from socket during interperate_server_response function", LOG_ERR);
		}
		i++;
	} while((i<sizeof(server_response))&&(server_response[i-1]!=termination_char));
	return 0;
}

int32_t clear_socket(uint32_t socket)
{
	//Use recv with MSG_DONTWAIT flag in a loop
	char temp_byte_buffer[255] = {0};
	if(read(socket, temp_byte_buffer, sizeof(temp_byte_buffer))<0)
	{
		perror("read in clear_socket");
		return -1;
	}
	#ifdef DEBUG
	printf("Clearing socket\n");
	#endif /*DEBUG*/
	return 0;
}

int32_t this_is_the_end(uint32_t my_only_friend) //Input should be a socket
{
	if (write(my_only_friend, cmtp_command_OBAI, sizeof(cmtp_command_OBAI))<0)
	{
		perror("write");
		print_to_log("failed to write cmtp_command_OBAI.", LOG_ERR);
		return -1;
	}
	return 0;
}

//select_mail function returns a c string which corrosponds to the filesystem location of the mail to be read
int32_t select_mail(char * mail_directory, char * return_buffer, uint32_t return_buffer_length)
{
	char * dir;
	struct dirent *ent;
	uint32_t index = 0;
	uint32_t selection = 0;
	int32_t open_file = 0;
	if ((dir = opendir(mail_directory)) != NULL)
	{
	  while ((ent = readdir(dir))!=NULL)
		{
			if (((strcmp(ent->d_name, ".")==0)||(strcmp(ent->d_name, "..")==0)))
			{
				continue;
			}
	    printf ("%d: %s\n", index, ent->d_name);
			index++;
	  }
	  closedir (dir);
		char input_selection[10] = {0};
		if (prompt_input_string("Selection: ", "", input_selection, sizeof(input_selection))<0)
		{
			perror("prompt_input_string");
			print_to_log("Failed to get user input in mail selection", LOG_ERR);
			return -1;
		}
		//printf("atoi = %d\n", atoi(input_selection));
		selection = atoi(input_selection);
		if ((selection<0)||(selection>index))
		{
			perror("Bad file selection");
			return -1;{
	  perror ("opendir");
		print_to_log("Could not open directory", LOG_ERR);
	  return -1;
		}
		}
		else
		{
			if ((dir = opendir(mail_directory)) != NULL)
			{
				for(int i = 0; i<selection; i++)
				{
					if((ent=readdir(dir))!=NULL)
					{
						#ifdef DEBUG
						printf("Incrementing ent. ent->d_name = %s\n", ent->d_name);
						#endif /*DEBUG*/
						continue;
					}
					else
					{
						perror("readdir");
						closedir(dir);
						return -1;
					}
				}
				closedir(dir);
				char * selected_mail[512] = {0};
				snprintf(selected_mail, 512, "%s%c%s", mail_directory, '/', ent->d_name);
				if (return_buffer_length<(strlen(selected_mail)+1))
				{
					return -1;
				}
				memset(return_buffer, 0, (strlen(selected_mail)+1));
				memcpy(return_buffer, selected_mail, strlen(selected_mail));
				#ifdef DEBUG
				printf("Returning selected_mail =  %s\n", selected_mail);
				#endif /*DEBUG*/
				return 0;
			}
		}
	}
	else
	{
	  perror ("opendir");
		print_to_log("Could not open directory", LOG_ERR);
	  return -1;
	}
	return -1;
}

int32_t display_message(char * message_path, char * private_key_buffer, char * public_key_buffer, uint32_t key_version)
{
	int32_t mail_file_descriptor = 0;
	if((mail_file_descriptor = open(message_path, O_RDONLY))<0)
	{
		perror("open");
		print_to_log("Opening message to display has failed", LOG_ERR);
		return -1;
	}
	if (key_version!=1)
	{
		print_to_log("Incorrect key key_version", LOG_ERR);
		return -1;
	}
	//Header buffers
	uint32_t message_version = 0;
	uint32_t attachment_count = 0;
	uint64_t log_length = 0;
	uint64_t message_length = 0;
	char recipient[255] = {0};
	char recipient_domain[255] = {0};
	char sender[255] = {0};
	char sender_domain[255] = {0};
	if (read(mail_file_descriptor, message_version, 4)<0)
	{
		perror("read message_version");
		print_to_log("Failed to read first 4 bytes from mail_file_descriptor", LOG_ERR);
		return -1;
	}
	message_version = be32toh(message_version);
	if(message_version!=key_version)
	{
		perror("Version mismatch");
		print_to_log("Version difference between message beign read and key provided", LOG_ERR);
		return -1;
	}
	if (read(mail_file_descriptor, attachment_count, 4)<0)
	{
		perror("read attachment_count");
		print_to_log("Failed to read second 4 bytes from mail_file_descriptor", LOG_ERR);
		return -1;
	}
	attachment_count = be32toh(attachment_count);
	if (read(mail_file_descriptor, log_length, 4)<0)
	{
		perror("read log_length");
		print_to_log("Failed to read 8 bytes from mail_file_descriptor", LOG_ERR);
		return -1;
	}
	log_length = be64toh(log_length);
	if (read(mail_file_descriptor, message_length, 4)<0)
	{
		perror("read message_length");
		print_to_log("Failed to read 8 bytes from mail_file_descriptor", LOG_ERR);
		return -1;
	}
	message_length = be64toh(message_length);
	if (read_until(mail_file_descriptor, recipient, 255, '\0')<0)
	{
		perror("read_until");
		print_to_log("read_until failed to read message recipient", LOG_ERR);
		return -1;
	}
	if (read_until(mail_file_descriptor, recipient_domain, 255, '\0')<0)
	{
		perror("read_until");
		print_to_log("read_until failed to read message recipient_domain", LOG_ERR);
		return -1;
	}
	if (read_until(mail_file_descriptor, sender, 255, '\0')<0)
	{
		perror("read_until");
		print_to_log("read_until failed to read message sender", LOG_ERR);
		return -1;
	}
	if (read_until(mail_file_descriptor, sender_domain, 255, '\0')<0)
	{
		perror("read_until");
		print_to_log("read_until failed to read message sender_domain", LOG_ERR);
		return -1;
	}
	char * encrypted_message_body = calloc(1, message_length);
	char * plain_message_body = calloc(1, message_length);
	if(read_n_bytes(mail_file_descriptor, encrypted_message_body, message_length)<0)
	{
		perror("read_n_bytes");
		print_to_log("Reading ciphertext from mail_file_descriptor has failed", LOG_ERR);
		return -1;
	}
	if (crypto_box_seal_open(plain_message_body, encrypted_message_body, message_length, public_key_buffer, private_key_buffer) != 0)
	{
    perror("crypto_box_seal_open");
		print_to_log("crypto_box_seal_open failed to decrypt message", LOG_ERR);
		return -1;
	}

}
