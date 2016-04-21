#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <endian.h>
#include <pwd.h>
#include <fcntl.h>
#include <syslog.h>
#include <pthread.h>
#include <confuse.h>
#include <endian.h>

//Include header
#include "server_functions.h"

//Include crypto
#include <sodium.h>

//Include third party libraries
#include "../include/base64.h"
#include "cmtp_common.h"

//Available varibales

//Constants
const char cmtp_welcome[] = {"Welcome to CMTP version < 1\n"};
const char cmtp_ohai_response[] = {"HAI!!! :3\n"};
const char cmtp_noop[] = "O_O\n";
const char cmtp_help[] = "Commands: OHAI, MAIL, HELP, NOOP, KEYREQUEST, OBAI\n";
const char cmtp_obai[] = "Good bye\n";
const char cmtp_login[] = "T_T\n";
const char cmtp_command_OHAI[] = {"OHAI"};
const char cmtp_command_MAIL[] = {"MAIL"};
const char cmtp_command_HELP[] = {"HELP"};
const char cmtp_command_NOOP[] = {"NOOP"};
const char cmtp_command_LOGIN[] = {"LOGIN"};
const char cmtp_command_OBAI[] = {"OBAI"};
const char cmtp_command_KEYREQUEST[] = {"KEYREQUEST"};
const char cmtp_reply_KEYNOTAVAILABLE[] = {"KEYNOTAVAILABLE"};
const char termination_char = '\0';
const uint32_t crypto_version = 1;
uint32_t network_crypto_version = 0;
char home_domain[64] = {0};
uint32_t MAX_CONNECTIONS = 10;

//Store signing keys. Can regenerate box keys from these.
static unsigned char server_public_key[crypto_sign_ed25519_PUBLICKEYBYTES] = {0};
static unsigned char server_private_key[crypto_sign_ed25519_SECRETKEYBYTES] = {0};

/*
Ensure that server has everything it needs to begin operation.
@return -1 on failure, a socket file descriptor on success.
*/
int server_init(struct init_params * passback_params)
{
  static uint32_t system_init = 0;
  static uint32_t server_socket = 0;
  static struct sockaddr_in server_address;

  if (system_init != 1)
  {
    //Init log with the binary name
    initlog("cmtpd");
    print_to_log("cmtpd started", LOG_INFO);

    //Set working variables
    char * jail_directory = "/var/cmtp";
    char * working_user = "nobody";
    char * config_file = "/etc/cmtpd/cmtpd.conf";
    struct config_struct working_config;
    network_crypto_version = htobe32(crypto_version);

    if (getdomainname(home_domain, sizeof(home_domain))<0)
    {
      perror("getdomainname");
      print_to_log("getdomainname failure.", LOG_EMERG);
    }
    //Null domain case
    if (strlen(home_domain)==0)
    {
      print_to_log("Domain name null", LOG_EMERG);
      exit(1);
    }

    //Config file
    if (parse_config(config_file, &working_config)<0)
    {
      print_to_log("Cannot read config file. Proceeding with caution", LOG_ERR);
    }
    //Allows caller to know max connections
    passback_params->max_available_connections = working_config.max_connections;

    int32_t public_key_descriptor = -1;
    int32_t private_key_descriptor = -1;
    //Check for Keys
    create_verify_dir("/etc/cmtp/");
    if ((access("/etc/cmtp/public.key", R_OK)<0)||(access("/etc/cmtp/private.key",R_OK)<0))
    {
      printf("Attempting to create keys\n");
      //Key error has occured. At least one of the two keys does not exist. NUKE EVERYTHING!!! (ie. recreate keys).
      crypto_sign_ed25519_keypair(server_public_key, server_private_key);
      //print_buffer (server_public_key, 32, "server public key: ", 32, 1);
      if ((public_key_descriptor=open("/etc/cmtp/public.key", O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR))<0)
      {
        perror("open");
        print_to_log("Error opening public key. Cannot store public key", LOG_ERR);
      }
      if (write(public_key_descriptor, &server_public_key, sizeof(server_public_key))<0)
      {
        perror("write");
        print_to_log("Error writing public key. Cannot store public key", LOG_ERR);
      }
      if (close(public_key_descriptor)<0)
      {
        perror("close");
        print_to_log("Cannot close public key", LOG_ERR);
      }

      if ((private_key_descriptor=open("/etc/cmtp/private.key", O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR))<0)
      {
        perror("open");
        print_to_log("Error opening private key. Cannot store public key", LOG_ERR);
      }
      if (write(private_key_descriptor, &server_private_key, sizeof(server_private_key))<0)
      {
        perror("write");
        print_to_log("Error writing private key. Cannot store public key", LOG_ERR);
      }
      if (close(private_key_descriptor)<0)
      {
        perror("close");
        print_to_log("Cannot close private key", LOG_ERR);
      }
    }
    //Read in public and private Keys
    else if ((access("/etc/cmtp/public.key", R_OK)>=0)&&(access("/etc/cmtp/private.key",R_OK)>=0))
    {
      if ((public_key_descriptor = open("/etc/cmtp/public.key", O_RDONLY))<0)
      {
        perror("open");
        print_to_log("Cannot open public key. Error, Error!", LOG_CRIT);
        return -1;
      }
      if (read(public_key_descriptor, &server_public_key, sizeof(server_public_key))<0)
      {
        perror("read");
        print_to_log("Cannot read public key.", LOG_CRIT);
        return -1;
      }
      if (close(public_key_descriptor)<0)
      {
        perror("close");
        print_to_log("Cannot close public key", LOG_ERR);
      }
      if ((private_key_descriptor = open("/etc/cmtp/private.key", O_RDONLY))<0)
      {
        perror("open");
        print_to_log("Cannot open private key. Error, Error!", LOG_ERR);
      }
      if (read(private_key_descriptor, &server_private_key, sizeof(server_private_key))<0)
      {
        perror("read");
        print_to_log("Cannot read private key.", LOG_CRIT);
        return -1;
      }
      if (close(private_key_descriptor)<0)
      {
        perror("close");
        print_to_log("Cannot close private key", LOG_ERR);
      }
    }

    if ((create_verify_dir(jail_directory)<0))
    {
      exit(1);
    }

    //Configure server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    server_address.sin_port = htobe16(LISTEN_PORT);
  	server_address.sin_family = AF_INET;
  	server_address.sin_addr.s_addr = htobe32(INADDR_ANY);
    if (bind(server_socket,(struct sockaddr *)&server_address, sizeof(server_address)) < 0)
  	{
      print_to_log("Binding to local socket failed. Cannot continue", LOG_EMERG);
  		perror("Bind() on server_socket has failed\n");
      return -1;
  	}
  	if (listen(server_socket, 10) < 0)
  	{
      print_to_log("Listening on local socket has failed. Cannot continue", LOG_EMERG);
  		perror("Listen() on server_socket has failed\n");
      return -1;
  	}
    //Set ownership of /var/cmtp
    struct passwd * root_user_passwd;
    root_user_passwd = getpwnam("root");
    if (((chown(jail_directory, root_user_passwd->pw_uid, root_user_passwd->pw_gid))==1))
    {
      perror("chown");
      print_to_log("chown of working directories failed. Cannot proceed.", LOG_EMERG);
      exit(1);
    }

    if (init_jail(jail_directory)<0)
    {
      print_to_log("init_jail returned -1. Cannot proceed", LOG_EMERG);
      exit(1);
    }
    if (enter_jail(jail_directory, working_user))
    {
      print_to_log("enter_jail returned -1. Cannot proceed", LOG_EMERG);
      exit(1);
    }
    system_init = 1;
  }
  //Check config files in /etc/cmtp. Parse and load if they do.
  print_to_log("cmtp init finished.", LOG_INFO);
  return server_socket;
}

//Each connection (post OHAI) should be handled in a single thread. This is done to avoid global state.
//argument will be a struct (what struct remains to be determined)
/*
arguement needs to contain
file descriptor of the connection
... and more? maybe?
*/
void * connection_manager(void * connection_manager_argument)
{
  #ifdef DEBUG
  printf("Begin connection manager.\n");
  #endif /*DEBUG*/
  print_to_log("Connection made. Begining CMTP session.",LOG_INFO);
  #define THREAD_COMMAND_BUFFER_SIZE 11
  #define ROUTING_FIELD_SIZE 255

  uint32_t i = 0;
  uint32_t thread_connection = *(uint32_t *) connection_manager_argument;
  free(connection_manager_argument);
  write(thread_connection, cmtp_welcome, sizeof(cmtp_welcome));

  //char mail_message_buffer[MAIL_READ_BUFFER];
  char thread_command_buffer[THREAD_COMMAND_BUFFER_SIZE] = {0};
  char bad_state_buffer[] = "Error";

  while (1)
  {
    i = 0;
    //Read in commmand
    do {
      read(thread_connection, thread_command_buffer+i, 1);
      i++;
    } while((i<sizeof(thread_command_buffer))&&(thread_command_buffer[i-1]!=termination_char));

    //OHAI
    if (memcmp(cmtp_command_OHAI, thread_command_buffer, sizeof(cmtp_command_OHAI))==0)
    {
      ohai_responder(thread_connection);
      memset(thread_command_buffer, 0, sizeof(thread_command_buffer));
    }

    //KEYREQUEST <USER> <DOMAIN>
    //Should send the crypto_type (All 4 bytes!) followed by the public key of the null terminated user followed by the server signature of the users public key.
    if (i==11&&memcmp(cmtp_command_KEYREQUEST, thread_command_buffer, sizeof(cmtp_command_KEYREQUEST))==0)
    {
      keyrequest_responder(thread_connection);
      memset(thread_command_buffer, 0, sizeof(thread_command_buffer));
    }

    //NOOP
    if (memcmp(cmtp_command_NOOP, thread_command_buffer, sizeof(cmtp_command_NOOP))==0)
    {
      int32_t noop_responder(uint32_t socket);
      memset(thread_command_buffer, 0, sizeof(thread_command_buffer));
    }

    //LOGIN <USER>
    //How a user initiates a login. For now server will simply send public and private keys to the user.
    //In the future this can be made more elaborate with the user signing something to prove they can decrypt the private key.
    if (memcmp(cmtp_command_LOGIN, thread_command_buffer, sizeof(cmtp_command_LOGIN))==0)
    {
      login_responder(thread_connection);
      memset(thread_command_buffer, 0, sizeof(thread_command_buffer));
    }

    //MAIL
    if (memcmp(cmtp_command_MAIL, thread_command_buffer, sizeof(cmtp_command_MAIL))==0)
    {
      mail_responder(thread_connection);
      memset(thread_command_buffer, 0, sizeof(thread_command_buffer));
    }
    //End MAIL section

    //HELP
    if (memcmp(cmtp_command_HELP, thread_command_buffer, sizeof(cmtp_command_HELP))==0)
    {
      help_responder(thread_connection);
      memset(thread_command_buffer, 0, sizeof(thread_command_buffer));
    }

    //OBAI
    if (memcmp(cmtp_command_OBAI, thread_command_buffer, 4)==0)
    {
      obai_responder(thread_connection);
      memset(thread_command_buffer, 0, sizeof(thread_command_buffer));
      return NULL;
    }
  }
}

/*
Forwards a message to its' destination.
@param File descriptor of the message.   <---- change to char * and get FD off that
@param Destination server as a c string.
@return
*/
int forwardMessage(char * file_to_foward, char * dest_server_string)
{
  print_to_log("Forward message routine starting.", LOG_INFO);
  //Find MX record
  struct sockaddr_storage dest_sockaddr;
  int32_t file_to_foward_descriptor;
  uint32_t mx_family = -1;
  mx_family = resolve_server(dest_server_string, &dest_sockaddr);
  uint32_t temp_socket = 0;

  if ((mx_family!=AF_INET)&&(mx_family!=AF_INET6))
  {
    #ifdef DEBUG
    printf("Invalid mx_family. Cannot forward mail. mx_family = %d\n", mx_family);
    #endif /*DEBUG*/
    print_to_log("Invalid MX family on message forward. Cannot forward message.", LOG_INFO);
    return -1;
  }

  //IPv4 case
  if(mx_family==AF_INET)
  {
    temp_socket = socket(AF_INET, SOCK_STREAM, 0);
    if ((connect(temp_socket, (struct sockaddr_in *)&dest_sockaddr, sizeof(struct sockaddr_in)))<0)
    {
      print_to_log("Connecting on send port has failed. Cannot forward message.", LOG_ERR);
      perror("connect");
      return -1;
    }

    //Write file to connected socket
    char temp_byte;
    if ((file_to_foward_descriptor = open(file_to_foward, O_RDONLY))<0)
    {
      print_to_log("Cannot open file for forwarding.", LOG_ERR);
      return -1;
    }
    while ((temp_byte=read(file_to_foward_descriptor, &temp_byte, 1))!=-1)
    {
      write(temp_socket, &temp_byte, 1);
    }
    #ifdef DEBUG
    printf("Message forwarded via IPv4\n");
    #endif /*DEBUG*/
    print_to_log("Forward message via IPv4 complete", LOG_INFO);
  }

  if(mx_family==AF_INET6)
  {
    temp_socket = socket(AF_INET6, SOCK_STREAM, 0);
    if ((connect(temp_socket, (struct sockaddr_in6 *)&dest_sockaddr, sizeof(struct sockaddr_in6)))<0)
    {
      print_to_log("Connecting on send port has failed. Cannot forward message.", LOG_ERR);
      perror("connect");
      return -1;
    }

    //Write file to connected socket
    char temp_byte;
    while ((temp_byte=read(file_to_foward_descriptor, &temp_byte, 1))!=-1)
    {
      write(temp_socket, &temp_byte, 1);
    }
    print_to_log("Forward message via IPv6 complete", LOG_INFO);
  }
  close(temp_socket);
  return 0;
}

/*
Function to parse the server config file.
@param Config file location in the file system.
@param Struct to write results into.
@return -1 on failure, 0 on success.
*/
int parse_config(char * config_file, struct config_struct * running_config)
{
  print_to_log("Parsing config file", LOG_INFO);
  cfg_opt_t opts[] =
	{
	  CFG_STR("domain", "", CFGF_NONE),
    CFG_INT("connection_timeout_in_seconds", 0, CFGF_NONE),
    CFG_INT("max_connections", 0, CFGF_NONE),
	  CFG_END()
	};
	cfg_t *cfg;
	cfg = cfg_init(opts, CFGF_NONE);
	 if(cfg_parse(cfg, config_file) == CFG_PARSE_ERROR)
   {
     printf("Reading config %s has failed\n", config_file);
     return -1;
   }
   if (strcmp(cfg_getstr(cfg, "domain"),"")!=0)
   {
     //Load domain into struct here.
   }
   if (cfg_getint(cfg, "connection_timeout_in_seconds")<=60)
   {
     //load connection_timeout_in_seconds into struct here.
     running_config->connection_timeout_in_seconds = cfg_getint(cfg, "connection_timeout_in_seconds");
   }
   if (cfg_getint(cfg, "max_connections")<=1000)
   {
     //load connection_timeout_in_seconds into struct here.
     running_config->max_connections = cfg_getint(cfg, "max_connections");
   }
   return 0;
}

int32_t ohai_responder(uint32_t socket)
{
  if (write(socket, cmtp_ohai_response, sizeof(cmtp_ohai_response))<0)
  {
    perror("ohai write");
    print_to_log("Error writing in ohai_responder", LOG_ERR);
    return -1;
  }
  return 0;
}

int32_t keyrequest_responder(uint32_t socket)
{
  //Read until null
  uint32_t i = 0;
  char base64_username[341] = {0};
  char pub_key_path[358] = {0};
  char user_keyrequest_buffer[ROUTING_FIELD_SIZE] = {0};
  char domain_keyrequest_buffer[ROUTING_FIELD_SIZE] = {0};
  unsigned char user_public_key[crypto_sign_ed25519_PUBLICKEYBYTES] = {0};
  unsigned char signature_of_public_key[crypto_sign_BYTES] = {0};
  unsigned char signature_of_KEYNOTAVAILABLE[crypto_sign_BYTES] = {0};
  unsigned char write_buffer[sizeof(network_crypto_version)+sizeof(server_public_key)+sizeof(signature_of_public_key)+2];
  //Read in username
  do {
    read(socket, user_keyrequest_buffer+i, 1);
    //printf("user_keyrequest_buffer[%d] = %c/%x\n",i,user_keyrequest_buffer[i], user_keyrequest_buffer[i]);
    i++;
  } while((i<sizeof(user_keyrequest_buffer))&&(user_keyrequest_buffer[i-1]!='\0'));
  if (memcmp(user_keyrequest_buffer, &termination_char, 1)==0)
  {
    crypto_sign_detached(signature_of_public_key, NULL, server_public_key, sizeof(server_public_key), server_private_key);
    #ifdef DEBUG
    //print_buffer (server_private_key, 64, "server private key: ", 64, 1);
    //print_buffer (server_public_key, 32, "server public key: ", 32, 1);
    //print_buffer (signature_of_public_key, 64, "server public key signature: ", 64, 1);
    crypto_sign_verify_detached(signature_of_public_key, server_public_key, crypto_sign_ed25519_PUBLICKEYBYTES, server_public_key);
    #endif /*DEBUG*/

    //Wants server key. Reply and return.
    //Create single buffer
    memcpy(write_buffer, &network_crypto_version, sizeof(network_crypto_version));
    memcpy(write_buffer+sizeof(network_crypto_version), server_public_key, sizeof(server_public_key));
    memcpy(write_buffer+sizeof(network_crypto_version)+sizeof(server_public_key), &termination_char, sizeof(termination_char));
    memcpy(write_buffer+sizeof(network_crypto_version)+sizeof(server_public_key)+sizeof(termination_char), signature_of_public_key, sizeof(signature_of_public_key));
    memcpy(write_buffer+sizeof(network_crypto_version)+sizeof(server_public_key)+sizeof(termination_char)+sizeof(signature_of_public_key), &termination_char, sizeof(termination_char));
    write(socket, write_buffer, sizeof(write_buffer));
    // write(socket, server_public_key, sizeof(server_public_key));
    // write(socket, &termination_char, sizeof(termination_char));
    // write(socket, signature_of_public_key, sizeof(signature_of_public_key));
    // write(socket, &termination_char, sizeof(termination_char));
    return 0;
    //Need to end here. Might need to functionize this code.
  }
  else
  {
    //uint32_t base64_username_length = base64_encode((char *)user_keyrequest_buffer, strlen(user_keyrequest_buffer), base64_username, strlen(base64_username), (char *)filesystem_safe_base64_string, 64);
    #ifdef DEBUG
    printf("Requested user = %s\n", user_keyrequest_buffer);
    #endif /*DEBUG*/
    do {
      read(socket, domain_keyrequest_buffer+i, 1);
      i++;
    } while((i<sizeof(domain_keyrequest_buffer))&&(domain_keyrequest_buffer[i-1]!='\0'));

    if (memcmp(&domain_keyrequest_buffer, &home_domain, ROUTING_FIELD_SIZE)!=0)
    {
      //Keyrequest is for a different domain. Query that domain and relay key.
    }

    if (snprintf(pub_key_path, sizeof(pub_key_path), "%s%s%s", "/mail/", user_keyrequest_buffer, "/public.key")<0)
    {
      perror("snprintf");
      print_to_log("snprintf error. Cannot check for user public key", LOG_ERR);
    }
    //Check for user's key in /mail/base64_username/public.key
    if (access(pub_key_path, R_OK)<0)
    {
      //User does not exist. Send error.
      perror("user access");
      #ifdef DEBUG
      printf("Key not found at %s\n", pub_key_path);
      #endif /*DEBUG*/
      print_to_log("Cannot access user public key. User does not exist.", LOG_ERR);
      //cmtp_reply_KEYNOTAVAILABLE includes the trailing null!
      crypto_sign_detached(signature_of_KEYNOTAVAILABLE, NULL, (const unsigned char *)cmtp_reply_KEYNOTAVAILABLE, sizeof(cmtp_reply_KEYNOTAVAILABLE), server_private_key);

      memcpy(write_buffer, &network_crypto_version, sizeof(network_crypto_version));
      memcpy(write_buffer+sizeof(cmtp_reply_KEYNOTAVAILABLE), cmtp_reply_KEYNOTAVAILABLE, sizeof(cmtp_reply_KEYNOTAVAILABLE));
      memcpy(write_buffer+sizeof(network_crypto_version)+sizeof(cmtp_reply_KEYNOTAVAILABLE), &signature_of_KEYNOTAVAILABLE, sizeof(signature_of_KEYNOTAVAILABLE));
      memcpy(write_buffer+sizeof(network_crypto_version)+sizeof(cmtp_reply_KEYNOTAVAILABLE)+sizeof(signature_of_KEYNOTAVAILABLE), signature_of_public_key, sizeof(signature_of_public_key));
      memcpy(write_buffer+sizeof(network_crypto_version)+sizeof(cmtp_reply_KEYNOTAVAILABLE)+sizeof(signature_of_KEYNOTAVAILABLE)+sizeof(signature_of_public_key), &termination_char, sizeof(termination_char));
      #ifdef DEBUG
      //print_buffer (cmtp_reply_KEYNOTAVAILABLE, 32, "Key not available message: ", 32, 1);
      //print_buffer (signature_of_public_key, 64, "Key not available signature: ", 64, 1);
      #endif /*DEBUG*/
      write(socket, write_buffer, sizeof(write_buffer));

      // write(socket, &network_crypto_version, sizeof(network_crypto_version));
      // write(socket, cmtp_reply_KEYNOTAVAILABLE, sizeof(cmtp_reply_KEYNOTAVAILABLE));
      // write(socket, signature_of_KEYNOTAVAILABLE, sizeof(signature_of_KEYNOTAVAILABLE));
      // write(socket, &termination_char, sizeof(termination_char));

    }
    else         //Read public key and reply to request with it.
    {
      int32_t user_key_descriptor = open(pub_key_path, O_RDONLY);
      if (user_key_descriptor<0)
      {
        perror("open");
        print_to_log("Cannot open user public key", LOG_ERR);
      }
      if (read(user_key_descriptor, user_public_key, sizeof(user_public_key))<0)
      {
        perror("read");
        print_to_log("Error reading user public key", LOG_ERR);
      }
      //Sign key and store signature in signature_of_public_key
      crypto_sign_detached(signature_of_public_key, NULL, user_public_key, sizeof(user_public_key), server_private_key);
      //Send it all
      memcpy(write_buffer, &network_crypto_version, sizeof(network_crypto_version));
      memcpy(write_buffer+sizeof(network_crypto_version), user_public_key, sizeof(user_public_key));
      memcpy(write_buffer+sizeof(network_crypto_version)+sizeof(user_public_key), &termination_char, sizeof(termination_char));
      memcpy(write_buffer+sizeof(network_crypto_version)+sizeof(user_public_key)+sizeof(termination_char), signature_of_public_key, sizeof(signature_of_public_key));
      memcpy(write_buffer+sizeof(network_crypto_version)+sizeof(user_public_key)+sizeof(termination_char)+sizeof(signature_of_public_key), &termination_char, sizeof(termination_char));
      #ifdef DEBUG
      //print_buffer (user_public_key, 32, "User public key: ", 32, 1);
      //print_buffer (signature_of_public_key, 64, "User public key signature: ", 64, 1);
      #endif /*DEBUG*/
      write(socket, write_buffer, sizeof(write_buffer));

      // write(socket, &network_crypto_version, sizeof(network_crypto_version));
      // write(socket, user_public_key, sizeof(user_public_key));
      // write(socket, &termination_char, sizeof(termination_char));
      // write(socket, signature_of_public_key, sizeof(signature_of_public_key));
      // write(socket, &termination_char, sizeof(termination_char));
      printf("Sent %ld bytes\n", sizeof(network_crypto_version)+sizeof(user_public_key)+sizeof(termination_char)+sizeof(signature_of_public_key)+sizeof(termination_char));
    }
  }
  //Clean buffers
  memset(user_keyrequest_buffer, 0, sizeof(user_keyrequest_buffer));
  memset(base64_username, 0, sizeof(base64_username));
  return 0;
}

int32_t noop_responder(uint32_t socket)
{
  if (write(socket, cmtp_noop, sizeof(cmtp_noop))<0)
  {
    perror("noop write");
    print_to_log("Error writing to socket in noop_responder", LOG_ERR);
    return -1;
  }
  return 0;
}

int32_t login_responder(uint32_t socket)
{
  char login_username_buffer[ROUTING_FIELD_SIZE] = {0};
  char login_command_buffer[THREAD_COMMAND_BUFFER_SIZE] = {0};
  char base64_username[341] = {0};
  char priv_key_path[359] = {0};
  uint32_t i = 0;

  write(socket, cmtp_login, sizeof(cmtp_login));
  //This do loop should not need a command buffer. Wtf was I thinking?
  do {
    read(socket, login_username_buffer+i, 1);
    i++;
  } while((i<sizeof(login_command_buffer))&&(login_command_buffer[i-1]!=termination_char));
  uint32_t base64_username_length = base64_encode((char *)login_username_buffer, strlen(login_username_buffer), base64_username, strlen(base64_username), (char *)filesystem_safe_base64_string, 64);
  if (snprintf(priv_key_path, sizeof(priv_key_path), "%s%s%s", "/mail/", base64_username, "/private.key")<0)
  {
    perror("snprintf");
    print_to_log("snprintf error. Cannot check for user public key", LOG_ERR);
  }

  if (access(priv_key_path,R_OK)<0)
  {
    perror("access to private key");
    print_to_log("Cannot access user private key. User not registerd", LOG_ERR);
  }
  else
  {
    //read private key and send along with item to be signed.
  }
  return 0;
}

int32_t mail_responder(uint32_t socket)
{
  #ifdef DEBUG
  printf("Entering MAIL subroutine\n");
  #endif /*DEBUG*/
  //Allocate general variables

  //Allocate primary buffers and counters
  char source_account_buffer[ROUTING_FIELD_SIZE];
  int32_t source_account_length = 0;
  char source_domain_buffer[ROUTING_FIELD_SIZE];
  int32_t source_domain_length = 0;
  char dest_account_buffer[ROUTING_FIELD_SIZE];
  int32_t dest_account_length = 0;
  char dest_domain_buffer[ROUTING_FIELD_SIZE];
  int32_t dest_domain_length = 0;
  uint32_t version = 0;
  uint32_t attachment_count = 0;
  uint64_t message_length = 0;
  uint64_t log_length = 0;
  //Generate unique file from current time and current FD
  //Get time with nanosecond resolution (or so they say)
  struct timespec time_for_file;
  clock_gettime(CLOCK_REALTIME, &time_for_file);
  //Mix time with FD and hash
  //We are hashing two ints and a long, so
  char meat_and_potatoes[24] = {0};
  //memset(meat_and_potatoes, 0, sizeof(meat_and_potatoes));
  memcpy(meat_and_potatoes, &time_for_file.tv_sec, sizeof(time_for_file.tv_sec));
  memcpy(meat_and_potatoes+sizeof(time_for_file.tv_sec), &socket, sizeof(socket));
  memcpy(meat_and_potatoes+sizeof(time_for_file.tv_sec)+sizeof(socket), &time_for_file.tv_nsec, sizeof(time_for_file.tv_nsec));
  unsigned char hash[64]; //64 bytes because hash has a fixed size output
  crypto_generichash(hash, sizeof(hash), (const unsigned char *)meat_and_potatoes, sizeof(meat_and_potatoes),NULL, 0);

  //Get file ready to write
  //TODO needs to be /mail/user/unique_file_name
  char unique_file_name[129] = {0};

  //char base64_username[341] = {0};
  char unique_file_location[522] = {0};
  //TODO Need to check if user is part of this domain. If not the file location should be some temporary storage.

  //unique_file_name_length is not currently used. Should be fine.
  uint32_t unique_file_name_length = base64_encode((char *)hash, sizeof(hash), unique_file_name, sizeof(unique_file_name), (char *)filesystem_safe_base64_string, 64);
  //uint32_t base64_username_length = base64_encode((char *)dest_account_buffer, strlen(dest_account_buffer), base64_username, strlen(base64_username), (char *)filesystem_safe_base64_string, 64);

  if (snprintf(unique_file_location, sizeof(unique_file_location), "%s%s%s", "/mail/", dest_account_buffer, unique_file_name)<0)
  {
    perror("snprintf");
    print_to_log("snprintf failed to create a new file string. Cannot write message out",LOG_ERR);
    return -1;
  }
  #ifdef DEBUG
  printf("Writing mail to %s\n", unique_file_location);
  #endif /*DEBUG*/

  //Read primary routing and processing information
  //First read in fixed length fields
  if (read_n_bytes(socket, (char *)&version, 4)!=4)
  {
    perror("read_n_bytes version");
    print_to_log("Read error while reading crypto type", LOG_ERR);
    return -1;
  }
  write_to_file((char *)&version, 4, unique_file_location);
  version = be32toh(version);
  #ifdef DEBUG
  printf("Version = %d\n", version);
  #endif /*DEBUG*/
  if (read_n_bytes(socket, (char *)&attachment_count, 4)!=4)
  {
    perror("read_n_bytes attachment_count");
    print_to_log("Read error while reading attachment count", LOG_ERR);
    return -1;
  }
  #ifdef DEBUG
  printf("Attachment count = %d\n", attachment_count);
  #endif /*DEBUG*/
  write_to_file((char *)&attachment_count, 4, unique_file_location);
  attachment_count = be32toh(attachment_count);
  if (read_n_bytes(socket, (char *)&log_length, 8)!=8)
  {
    perror("read_n_bytes log_length");
    print_to_log("Read error while reading message length", LOG_ERR);
    return -1;
  }
  #ifdef DEBUG
  printf("Log length = %ld\n", log_length);
  #endif /*DEBUG*/
  write_to_file((char *)&log_length, 8, unique_file_location);
  log_length = be64toh(log_length);
  if (read_n_bytes(socket, (char *)&message_length, 8)!=8)
  {
    perror("read_n_bytes message_length");
    print_to_log("Read error while reading message length", LOG_ERR);
    return -1;
  }
  write_to_file((char *)&message_length, 8, unique_file_location);
  message_length = be64toh(message_length);
  #ifdef DEBUG
  printf("Message length = %ld\n", message_length);
  #endif /*DEBUG*/
  //Read in account and domain info
  if ((dest_account_length=read_until(socket, dest_account_buffer, sizeof(dest_account_buffer), '\0'))<0)
  {
    perror("read_until");
    print_to_log("Read error while reading dest_account_buffer", LOG_ERR);
    return -1;
  }
  write_to_file(dest_account_buffer, dest_account_length, unique_file_location);
  #ifdef DEBUG
  printf("dest_account_length = %d\n", dest_account_length);
  #endif /*DEBUG*/
  if ((dest_domain_length=read_until(socket, dest_domain_buffer, sizeof(dest_domain_buffer), '\0'))<0)
  {
    perror("read_until");
    print_to_log("Read error while reading dest_domain_buffer", LOG_ERR);
    return -1;
  }
  write_to_file(dest_domain_buffer, dest_domain_length, unique_file_location);
  #ifdef DEBUG
  printf("dest_domain_length = %d\n", version);
  #endif /*DEBUG*/
  if ((source_account_length=read_until(socket, source_account_buffer, sizeof(source_account_buffer), '\0'))<0)
  {
    perror("read_until");
    print_to_log("Read error while reading source_account_buffer", LOG_ERR);
    return -1;
  }
  write_to_file(source_account_buffer, source_account_length, unique_file_location);
  #ifdef DEBUG
  printf("source_account_length = %d\n", version);
  #endif /*DEBUG*/
  if ((source_domain_length=read_until(socket, source_domain_buffer, sizeof(source_domain_buffer), '\0'))<0)
  {
    perror("read_until");
    print_to_log("Read error while reading source_domain_buffer", LOG_ERR);
    return -1;
  }
  write_to_file(source_domain_buffer, source_domain_length, unique_file_location);
  #ifdef DEBUG
  printf("source_domain_length = %d\n", version);
  #endif /*DEBUG*/
  //This completes the read of the header


  //uint64_t numeric_message_length = be64toh(*(uint64_t*)(&(message_length[0])));
  //uint64_t numeric_log_length = be64toh(*(uint64_t*)(&(log_length[0])));

  char temp_byte[1] = {0};
  //Read log
  for (uint64_t i = 0; i<log_length; i++)
  {
    if (read(socket, temp_byte, 1)<1)
    {
      print_to_log("read error while reading message body", LOG_ERR);
      perror("read");
      return -1;
    }
    write_to_file(temp_byte, 1, unique_file_location);
  }
  //Read message body
  for (uint64_t i = 0; i<message_length; i++)
  {
    if (read(socket, temp_byte, 1)<1)
    {
      print_to_log("read error while reading message body", LOG_ERR);
      perror("read");
      return -1;
    }
    write_to_file(temp_byte, 1, unique_file_location);
  }

  #ifdef DEBUG
  printf("Message body finished. Moving to attachment handling.\n");
  #endif /*DEBUG*/
  //Read for attachment
  //uint32_t numeric_attachment_count = be32toh(*(uint32_t*)(&(attachment_count[0])));
  temp_byte[0] = 0;
  for (uint64_t i = 0; i<attachment_count; i++)
  {
    if (read(socket, temp_byte, 1)<1)
    {
      print_to_log("read error while reading message body", LOG_ERR);
      perror("read");
      return -1;
    }
    write_to_file(temp_byte, 1, unique_file_location);
  }
  #ifdef DEBUG
  printf("Mail destin for %s\n", dest_domain_buffer);
  #endif /*DEBUG*/

  //Destination cases
   if ((memcmp(dest_domain_buffer, home_domain, dest_domain_length)==0)&&(memcmp(dest_account_buffer,"",1))==0)
   {
     #ifdef DEBUG
     printf("Devlivered mail is for server. Begin processing.\n");
     #endif /*DEBUG*/
     print_to_log("Mail has arrived for the server. Processing.",LOG_INFO);
     //Destination is this domain and for the server
   }
   else if ((memcmp(dest_domain_buffer, home_domain, dest_domain_length)==0))
   {
     #ifdef DEBUG
     printf("Devlivered mail is for a user on this domain. Store.\n");
     #endif /*DEBUG*/
     print_to_log("Mail has arrived for a user on this domain. Storing.",LOG_INFO);
     //Destination is for a user at this domain
   }
   else
   {
     #ifdef DEBUG
     printf("Devlivered mail is not destined for this domain. Forward to %s\n", dest_domain_buffer);
     #endif /*DEBUG*/
     print_to_log("Mail has arrived for another domain. Forwarding.",LOG_INFO);
     forwardMessage(unique_file_location, dest_domain_buffer);
     //Destination is on the web. Forward message.
   }
   #ifdef DEBUG
   printf("Mail section complete.\n");
   #endif /*DEBUG*/
   return 0;
}

int32_t help_responder(uint32_t socket)
{
  if (write(socket, cmtp_help, sizeof(cmtp_help))<0)
  {
    perror("help write");
    print_to_log("Error writing to socket in help_responder", LOG_ERR);
    return -1;
  }
  return 0;
}

int32_t obai_responder(uint32_t socket)
{
  if (write(socket, cmtp_obai, sizeof(cmtp_obai))<0)
  {
    perror("obai write");
    print_to_log("Error writing to socket in obai_responder", LOG_ERR);
    return -1;
  }
  #ifdef DEBUG
  printf("OBAI command recived. Killing connection %x with threadID %ld\n", socket, pthread_self());
  #endif /*DEBUG*/
  //Close out socket and end
  if (close(socket)!=0)
  {
    //Close failure
    print_to_log("Error closing connection", LOG_ERR);
    perror("Close FD error");
    return -1;
  }
  return 0;
}
