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
const char cmtp_noop[] = "O_O\n";
const char cmtp_help[] = "Commands: OHAI, MAIL, HELP, NOOP, KEYREQUEST, OBAI\n";
const char cmtp_obai[] = "Good bye\n";
const char cmtp_command_OHAI[] = {"OHAI\n"};
const char cmtp_command_MAIL[] = {"MAIL\n"};
const char cmtp_command_HELP[] = {"HELP\n"};
const char cmtp_command_NOOP[] = {"NOOP\n"};
const char cmtp_command_OBAI[] = {"OBAI\n"};
const char cmtp_command_KEYREQUEST[] = {"KEYREQUEST\n"};
char home_domain[64] = {0};

//Ensure that server socket is created and listening
//Returns socket file descriptor if able and -1 on error
int server_init()
{
  static int system_init = 0;
  static int server_socket = 0;
  static struct sockaddr_in server_address;

  if (system_init != 1)
  {
    //Init log with the binary name
    initlog("cmtpd");
    print_to_log("cmtpd started", LOG_INFO);

    //Set working variables
    char * mail_dir = "/var/cmtp";
    char * working_user = "nobody";
    char * config_file = "/etc/cmtpd/cmtpd.conf";

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
    //May rely on libconfig here... maybe libconfuse
    int config_file_descriptor = 0;
    if ((config_file_descriptor = open(config_file, O_RDONLY))>0)
    {
      //Read in public/private key
      //Read in config and override working variables
    }
    close(config_file_descriptor);

    if ((create_verify_dir(mail_dir)<0))
    {
      exit(1);
    }


    //Set ownership of /var/cmtp
    struct passwd * working_user_passwd;
    struct passwd * root_user_passwd;
    working_user_passwd = getpwnam(working_user);
    root_user_passwd = getpwnam("root");;
    if (((chown(mail_dir, root_user_passwd->pw_uid, root_user_passwd->pw_gid))==1))
    {
      perror("chown");
      print_to_log("chown of working directories failed. Cannot proceed.", LOG_EMERG);
      exit(1);
    }

    //Move to what will be the new root


    // print_to_log("cmtpd before chroot jail", LOG_INFO);
    //chroot to restrict scope of server operations. KILLS LOGGING! AND DNS! PERHAPS MORE!
    if (init_jail()<0)
    {
      print_to_log("init_jail returned -1. Cannot proceed", LOG_EMERG);
      exit(1);
    }
    if (enter_jail(mail_dir))
    {
      print_to_log("enter_jail returned -1. Cannot proceed", LOG_EMERG);
      exit(1);
    }
    // print_to_log("cmtpd after jail", LOG_INFO);

    //Drop privilage to nobody with nogroup

    if (set_privilage(working_user_passwd->pw_uid, working_user_passwd->pw_gid)<0)
    {
      print_to_log("Dropping privilage has failed. Terminating.", LOG_EMERG);
      exit(1);
    }


    //Set defaults for some variables and override if they are found in a config file
    //Perhaps have a -F flag for an alternate config file
    //Set filesystem usage limit in config file; 0 = unlimited


    //Configure server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    server_address.sin_port = htons(LISTEN_PORT);
  	server_address.sin_family = AF_INET;
  	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
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
void connection_manager(void * connection_manager_argument)
{
  #ifdef DEBUG
  printf("Begin connection manager.\n");
  #endif /*DEBUG*/
  print_to_log("Connection made. Begining CMTP session.",LOG_INFO);
  #define THREAD_COMMAND_BUFFER_SIZE 11
  #define ROUTING_FIELD_SIZE 255

  uint32_t i = 0;
  int thread_connection = *(int *) connection_manager_argument;
  free(connection_manager_argument);

  //char mail_message_buffer[MAIL_READ_BUFFER];
  char thread_command_buffer[THREAD_COMMAND_BUFFER_SIZE] = {0};
  char bad_state_buffer[] = "Error";

  while (1)
  {
    i = 0;
    //Read in commmand
    do {
      read(thread_connection, thread_command_buffer+i, 1);
      //printf("thread_command_buffer[%d] = %c/%x\n",i,thread_command_buffer[i], thread_command_buffer[i]);
      i++;
    } while((i<sizeof(thread_command_buffer))&&(thread_command_buffer[i-1]!='\n'));
    //Test for end of buffer
    //Send error to other end
    //Reset buffer and read again until newline

    //OHAI
    if (memcmp(cmtp_command_OHAI, thread_command_buffer, 4)==0)
    {
      write(thread_connection, cmtp_welcome, sizeof(cmtp_welcome));
      //Clean thread_command_buffer
      memset(thread_command_buffer, 0, sizeof(thread_command_buffer));
    }

    //KEYREQUEST
    //Should send the crypto_type (All 4 bytes!) followed by the server public key
    if (i==11&&memcmp(cmtp_command_KEYREQUEST, thread_command_buffer, sizeof(cmtp_command_KEYREQUEST))==0)
    {
      //Clean thread_command_buffer
      memset(thread_command_buffer, 0, sizeof(thread_command_buffer));
    }

    //NOOP
    if (memcmp(cmtp_command_NOOP, thread_command_buffer, 4)==0)
    {
      write(thread_connection, cmtp_noop, sizeof(cmtp_noop));
      //Clean thread_command_buffer
      memset(thread_command_buffer, 0, sizeof(thread_command_buffer));
    }

    //MAIL
    if (memcmp(cmtp_command_MAIL, thread_command_buffer, 4)==0)
    {
      #ifdef DEBUG
      printf("Entering MAIL subroutine\n");
      #endif /*DEBUG*/
      //Allocate general variables

      //Allocate primary buffers and counters
      char source_account_buffer[ROUTING_FIELD_SIZE];
      int source_account_counter = 0;
      char source_server_buffer[ROUTING_FIELD_SIZE];
      int source_server_counter = 0;
      char dest_account_buffer[ROUTING_FIELD_SIZE];
      int dest_account_counter = 0;
      char dest_server_buffer[ROUTING_FIELD_SIZE];
      int dest_server_counter = 0;
      char crypto_type[sizeof(uint32_t)] = {0};
      char attachment_count[sizeof(uint32_t)] = {0};
      char message_length[sizeof(uint64_t)] = {0};

      //Read primary routing and processing information
      do
      {
        if (read(thread_connection, source_account_buffer+source_account_counter, 1) < 1)
        {
          perror("read source_accout_buffer");
          return;
        }
        source_account_counter++;
      } while((source_account_counter<ROUTING_FIELD_SIZE)&&(source_account_buffer[source_account_counter-1]!='\0'));

      do {
        if (read(thread_connection, &source_server_buffer[source_server_counter], 1) < 1)
        {
          perror("read source_server_buffer");
          return;
        }
        source_server_counter++;
      } while((source_server_counter<ROUTING_FIELD_SIZE)&&(source_server_buffer[source_server_counter-1]!='\0'));

      do {
        if (read(thread_connection, dest_account_buffer+dest_account_counter, 1) < 1)
        {
          perror("read dest_account_buffer");
          return;
        }
        dest_account_counter++;
      } while((dest_account_counter<ROUTING_FIELD_SIZE)&&(dest_account_buffer[dest_account_counter-1]!='\0'));

      do {
        if (read(thread_connection, dest_server_buffer+dest_server_counter, 1) < 1)
        {
          perror("read dest_server_buffer");
          return;
        }
        dest_server_counter++;
      } while((dest_server_counter<ROUTING_FIELD_SIZE)&&(dest_server_buffer[dest_server_counter-1]!='\0'));

      //Generate unique file from current time and current FD
      //Get time with nanosecond resolution (or so they say)
      struct timespec time_for_file;
      clock_gettime(CLOCK_REALTIME, &time_for_file);
      //Mix time with FD and hash
      //We are hashing two ints and a long, so
      char meat_and_potatoes[24] = {0};
      //memset(meat_and_potatoes, 0, sizeof(meat_and_potatoes));
      memcpy(meat_and_potatoes, &time_for_file.tv_sec, sizeof(time_for_file.tv_sec));
      memcpy(meat_and_potatoes+sizeof(time_for_file.tv_sec), &thread_connection, sizeof(thread_connection));
      memcpy(meat_and_potatoes+sizeof(time_for_file.tv_sec)+sizeof(thread_connection), &time_for_file.tv_nsec, sizeof(time_for_file.tv_nsec));
      unsigned char hash[64]; //64 bytes because hash has a fixed size output
      crypto_generichash(hash, sizeof(hash), (const unsigned char *)meat_and_potatoes, sizeof(meat_and_potatoes),NULL, 0);

      //Get file ready to write
      char unique_file_name[129] = {0};
      //unique_file_name_length is not currently used. Should be fine.
      int unique_file_name_length = base64_encode((char *)hash, sizeof(hash), unique_file_name, sizeof(unique_file_name), (char *)filesystem_safe_base64_string, 64);

      write_to_file(source_account_buffer, source_account_counter, unique_file_name);
      write_to_file(source_server_buffer, source_server_counter, unique_file_name);
      write_to_file(dest_account_buffer, dest_account_counter, unique_file_name);
      write_to_file(dest_server_buffer, dest_server_counter, unique_file_name);

      //crypto_type, attachment_count, and message_length are fixed size buffers
      if (read(thread_connection, crypto_type, 4) < 4)
      {
        print_to_log("Read error while reading crypto type", LOG_ERR);
        perror("read crypto_type");
        return;
      }
      write_to_file(crypto_type, 4, unique_file_name);
      if (read(thread_connection, attachment_count, 4) < 4)
      {
        print_to_log("Read error while reading attachment count", LOG_ERR);
        perror("read attachment_count");
        return;
      }
      write_to_file(attachment_count, 4, unique_file_name);
      if (read(thread_connection, message_length, 8) < 8)
      {
        print_to_log("Read error while reading message length", LOG_ERR);
        perror("read message_length");
        return;
      }
      write_to_file(message_length, 8, unique_file_name);
      //This completes the header of the message
      //Next we handle the body of the message
      uint64_t numeric_message_length = be64toh(*(uint64_t*)(&(message_length[0])));

      char temp_byte[1] = {0};
      #ifdef DEBUG
      //Might need funny stuff here
      //       printf("Message body length = %" PRId64 "\n", numeric_message_length);
      printf("Message body length = %jd\n", (intmax_t)numeric_message_length);
      #endif /*DEBUG*/
      for (uint64_t i = 0; i<numeric_message_length; i++)
      {
        if (read(thread_connection, temp_byte, 1)<1)
        {
          print_to_log("read error while reading message body", LOG_ERR);
          perror("read");
          return;
        }
        write_to_file(temp_byte, 1, unique_file_name);
      }

      #ifdef DEBUG
      printf("Message body finished. Moving to attachment handling.\n");
      #endif /*DEBUG*/
      //Read for attachment
      uint32_t numeric_attachment_count = be32toh(*(uint32_t*)(&(attachment_count[0])));
      temp_byte[0] = 0;
      for (uint64_t i = 0; i<numeric_attachment_count; i++)
      {
        if (read(thread_connection, temp_byte, 1)<1)
        {
          print_to_log("read error while reading message body", LOG_ERR);
          perror("read");
          return;
        }
        write_to_file(temp_byte, 1, unique_file_name);
      }

      //Destination cases
       if ((memcmp(dest_server_buffer, home_domain, dest_server_counter)==0)&&(memcmp(dest_account_buffer,0,1))==0)
       {
         #ifdef DEBUG
         printf("Devlivered mail is for server. Begin processing.\n");
         #endif /*DEBUG*/
         print_to_log("Mail has arrived for the server. Processing.",LOG_INFO);
         //Destination is this domain and for the server

       }
       else if ((memcmp(dest_server_buffer, home_domain, dest_server_counter)==0))
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
         printf("Devlivered mail is not destined for this domain. Forward to %s\n", dest_server_buffer);
         #endif /*DEBUG*/
         print_to_log("Mail has arrived for another domain. Forwarding.",LOG_INFO);
         forwardMessage(thread_connection, unique_file_name, dest_server_buffer);
         //Destination is on the web. Forward message.
       }

      //Clean thread_command_buffer
      #ifdef DEBUG
      printf("Mail section complete. Clearing buffer and returning.\n");
      #endif /*DEBUG*/
      memset(thread_command_buffer, 0, sizeof(thread_command_buffer));
    }
    //End MAIL section

    //HELP
    if (memcmp(cmtp_command_HELP, thread_command_buffer, 4)==0)
    {
      write(thread_connection, cmtp_help, sizeof(cmtp_help));

      //Clean thread_command_buffer
      memset(thread_command_buffer, 0, sizeof(thread_command_buffer));
    }

    //OBAI
    if (memcmp(cmtp_command_OBAI, thread_command_buffer, 4)==0)
    {
      write(thread_connection, cmtp_obai, sizeof(cmtp_obai));
      #ifdef DEBUG
      printf("OBAI command recived. Killing connection %x with threadID %ld\n", thread_connection, pthread_self());
      #endif /*DEBUG*/
      //Close out thread_connection and end
      if (close(thread_connection)!=0)
      {
        //Close failure
        print_to_log("Error closing connection", LOG_ERR);
        perror("Close FD error");
      }
      //Clean thread_command_buffer
      memset(thread_command_buffer, 0, sizeof(thread_command_buffer));
      return;
    }
  }
}


int forwardMessage(int connected_socket, int file_to_foward_descriptor, char * dest_server_string)
{
  print_to_log("Forward message routine starting.", LOG_INFO);
  //Find MX record
  struct sockaddr_storage dest_sockaddr;
  int mx_family = -1;
  mx_family = resolve_server(dest_server_string, &dest_sockaddr);
  int temp_socket = 0;

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
    // struct sockaddr_in temp_addr;
    // temp_addr.sin_port = htons(SEND_PORT);
    // temp_addr.sin_family = AF_INET;
    // server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    // if (bind(temp_socket, &temp_addr,sizeof(struct sockaddr_in))<0)
    // {
    //   print_to_log("Binding on send port has failed. Cannot forward message.", LOG_ERR);
    //   perror("Bind");
    //   return;
    // }
    if ((connect(temp_socket, (struct sockaddr_in *)&dest_sockaddr, sizeof(struct sockaddr_in)))<0)
    {
      print_to_log("Connecting on send port has failed. Cannot forward message.", LOG_ERR);
      perror("connect");
      return -1;
    }

    //Write file to connected socket
    char temp_byte;
    while ((temp_byte=read(file_to_foward_descriptor, temp_byte, 1))!=-1)
    {
      write(temp_socket, temp_byte, 1);
    }
    #ifdef DEBUG
    printf("Message forwarded via IPv4\n");
    #endif /*DEBUG*/
    print_to_log("Forward message via IPv4 complete", LOG_INFO);
  }

  if(mx_family==AF_INET6)
  {
    temp_socket = socket(AF_INET6, SOCK_STREAM, 0);
    // struct sockaddr_in temp_addr;
    // temp_addr.sin_port = htons(SEND_PORT);
    // temp_addr.sin_family = AF_INET;
    // server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    // if (bind(temp_socket, &temp_addr,sizeof(struct sockaddr_in))<0)
    // {
    //   print_to_log("Binding on send port has failed. Cannot forward message.", LOG_ERR);
    //   perror("Bind");
    //   return;
    // }
    if ((connect(temp_socket, (struct sockaddr_in6 *)&dest_sockaddr, sizeof(struct sockaddr_in6)))<0)
    {
      print_to_log("Connecting on send port has failed. Cannot forward message.", LOG_ERR);
      perror("connect");
      return -1;
    }

    //Write file to connected socket
    char temp_byte;
    while ((temp_byte=read(file_to_foward_descriptor, temp_byte, 1))!=-1)
    {
      write(temp_socket, temp_byte, 1);
    }
    print_to_log("Forward message via IPv6 complete", LOG_INFO);
  }

  close(temp_socket);


  //if (select_available_socket()>0)
  //{

  //}
  //Step 1: connect to dest_server
  //Step 2: Write message_buffer to connected socket
  return 0;
}

/*
Jail init function. Ensures that logging and DNS lookups will work from within the jail.
@return -1 on failure. 0 on success.
*/
int init_jail()
{
  print_to_log("Initializing cmtpd's jail.", LOG_INFO);
  create_verify_dir("/var/cmtp/etc");
  write_to_file(NULL, 0, "/var/cmtp/etc/resolv.conf");
  if(mount("/etc/resolv.conf", "/var/cmtp/etc/resolv.conf", 0, MS_BIND, 0)<0)
  {
    print_to_log("Cannot mount resolv.conf in jail.", LOG_EMERG);
    perror("mount");
    return -1;
  }
  create_verify_dir("/var/cmtp/dev");
  write_to_file(NULL, 0, "/var/cmtp/dev/log");
  if(mount("/dev/log", "/var/cmtp/dev/log", 0, MS_BIND, 0)<0)
  {
    print_to_log("Cannot mount /dev/log in jail.", LOG_EMERG);
    perror("mount");
    return -1;
  }
  print_to_log("jail has been created without error.", LOG_INFO);
  return 0;
}

int enter_jail(char * jail_dir)
{
  if (chdir(jail_dir)<0)
  {
    perror("chroot");
    print_to_log("chroot failed. Cannot jail cmptd.", LOG_EMERG);
    return -1;
  }
  if (chroot(jail_dir)<0)
  {
    perror("chroot");
    print_to_log("chroot failed. Cannot jail cmptd.", LOG_EMERG);
    return -1;
  }

  print_to_log("cmtp has entered its' jail.", LOG_INFO);
  return 0;
}

//dest_server should be fully qualified. ex. 'hawaii.edu'
//This function will be returning (or filling in) a sockaddr for use in a tcp connection
//Ideally the larger program will be able to do something like connect(resolve_server(hawaii.edu, 10))

//Function to send public key to anyone that asks
int sendKey(char * dest_server, int dest_server_length, char * user)
{
  //Step 1: Connect to dest_server
  //Step 2: Stick key in socket
  //Step 3: Hope dest_server gets it
  return 0;
}

/*server and server length should probably be a resolved IP structure... maybe*/
int requestKey(char * recieve_buffer, int recieve_length, char * account_requested, int request_length, char * server, int server_length)
{
  //Step 1: Look up MX record holder of server for account_requested
  //Step 2: Connect to the holder of the MX record
  //Step 3: Determin if holder is CMTP or SMTP
    //Step 3a: if SMTP then fail
  //Step 4: Send key request
  //Step 5 Await reply and pass reply to any waiting clients
  return 0;
}
