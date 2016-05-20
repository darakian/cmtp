// Copyright (c) 2015 by Jon Moroney. All Rights Reserved.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <fcntl.h>
#include <time.h>
#include <sodium.h>
#include <errno.h>
#include <pthread.h>
#include <pwd.h>
#include <sys/mount.h>


#include "../include/base64.h"
#include "cmtp_common.h"

static char log_identity[255];
static int loginit = 0;
static pthread_mutex_t dns_lock;


/*
Helper function to the DNS reslover function. This function just gets the last token in a string.
@param Pointer to the string.
@param Pointer to a string used as a delimiter.
@return Pointer to the last substring.
*/
char* last_str_split(char* a_str, const char * a_delim)
{
  char * token;
  char * temp_token;

  /* get the first token */
  temp_token = strtok(a_str, a_delim);

  /* walk through other tokens */
  while( temp_token != NULL )
  {
    token = temp_token;
    temp_token = strtok(NULL, a_delim);
  }

  return(token);
}


/*
Simple interface to provide DNS MX record resolution.
@param Pointer to the c string hostname you would like resolved to an MX record.
@param Pointer to the struct you would like the results written out to.
@return Return is of type int and is just the mx family type in the variable ohana. Ohana is hawaiian for family.
*/
int resolve_server(char * hostname, struct sockaddr_storage * result)
{
  pthread_mutex_lock(&dns_lock);
  res_init();
  int error = 0;
  int ohana = 0;
  ns_msg msg;
  ns_rr rr;
  struct addrinfo * addr_res;
  int res_length = 0;
  unsigned char dns_answer[4096] = {0};
  char display_buffer[4096] = {0};

  res_length = res_query(hostname, C_IN, T_MX, dns_answer, sizeof(dns_answer));
  if (ns_initparse(dns_answer, res_length, &msg)<0)
  {
    printf("hostname = %s\n", hostname);
    printf("res_length = %d\n", res_length);
    perror("DNS has gone wrong!");
    print_to_log("DNS resource query has failed", LOG_ERR);
  }
  else
  {
    res_length = ns_msg_count(msg, ns_s_an);
    for (int i = 0; i < res_length; i++)
    {
      //printf("DNS loop level = %d\n", i);
      ns_parserr(&msg, ns_s_an, i, &rr);
      ns_sprintrr(&msg, &rr, NULL, NULL, display_buffer, sizeof(display_buffer));
      if (ns_rr_type(rr) == ns_t_mx)
      {
        //String parsing solution for rr. Requires creation of display_buffer above
        error = getaddrinfo(last_str_split(display_buffer, " "), NULL, NULL, &addr_res);
        if (error != 0)
        {
          printf("error = %d\n", error);
          printf("display_buffer = %s\n", display_buffer);
          printf("last_str_split = %s\n", last_str_split(display_buffer, " "));
          perror("getaddrinfo");
        }
        if (addr_res->ai_family==AF_INET)
        {
          //printf("IPv4 mode is go\n");
          struct sockaddr_in* temp_addr = (struct sockaddr_in*)addr_res->ai_addr;
          memcpy(result, temp_addr, sizeof(*temp_addr));
          //printf("ai_addr hostname ->  %s\n", inet_ntoa(temp_addr->sin_addr));
          ohana = addr_res->ai_family;
        }
        else if (addr_res->ai_family==AF_INET6)
        {
          //printf("v6 mode engaged\n");
          struct sockaddr_in6 * temp_addr = (struct sockaddr_in6 *) addr_res->ai_addr;
          memcpy(result, temp_addr, sizeof(*temp_addr));
          ohana = addr_res->ai_family;
        }
      }
      freeaddrinfo(addr_res);
    }
  }
  pthread_mutex_unlock(&dns_lock);
  return ohana;
}

/*
Simple interface to write a buffer out to a file (and error check the process).
@param Pointer to the buffer which will be written out
@param Length of said buffer
@param Pointer to the c string which will be used as the filename (where the buffer gets written).
@return 0 on success, -1 on failure.
*/
int write_to_file(char * buffer, int buffer_length, char * filename)
{
  // #ifdef DEBUG
  // printf("Entering write_to_file subroutine\n");
  // #endif /*DEBUG*/
  int file_description = open(filename, O_WRONLY|O_APPEND|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
  if ((file_description)<0)
  {
    perror("write_to_file open");
    print_to_log("Error opening file", LOG_CRIT);
    return -1;
  }
  if (write(file_description, buffer, buffer_length)<1)
  {
    perror("write");
    print_to_log("Error writing to file", LOG_CRIT);
    return -1;
  }
  close(file_description);
  return 0;
}

/*
Function tries to create a directory and verifies that the directory is writable
@param path to attempt creation and verification on (c string).
@return 0 on success, -1 on failure.
*/
int create_verify_dir(char * path)
{
  #ifdef DEBUG
  printf("Entering create_verify_dir subroutine\n");
  printf("Attempting to create %s\n", path);
  #endif /*DEBUG*/
  char test_file[345] = {0};
  // temp_int = mkdir(path, S_IRWXU);
  // printf("temp_int = %d\n", temp_int);
  if (access(path, R_OK|W_OK)<0)
  {
    if (mkdir(path, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)<0)
    {
      if (errno!=EEXIST)
      {
        perror("mkdir");
        print_to_log("failed to create directory", LOG_INFO);
        print_to_log(path, LOG_INFO);
        return -1;
      }
    }
  }
  strcat(test_file, path);
  strcat(test_file, "/test");
  //Attempt to write a file to ensure writability
  int file_descriptor = (open(test_file, O_CREAT|O_RDWR, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH));
  if (file_descriptor== -1)
  {
    perror("create_verify_dir open");
    print_to_log("Opening test file failed. Cannot assume write access to working directory", LOG_CRIT);
    return -1;
  }
  if ((write(file_descriptor, path, sizeof(path)))<0)
  {
    perror("write");
    print_to_log("Writing to test file failed. Cannot assume write access to working directory", LOG_CRIT);
    return -1;
  }
  //Cleanup
  close(file_descriptor);
  remove(test_file);
  return 0;
}

/*
Makes an entry in syslog to enable future logging.
@param Name to be used for future log entries.
@return 0 on success, -1 on failure.
*/
int initlog(char * log_name)
{
  if (loginit!=0)
  {
    perror("Log already initialized");
    print_to_log("initlog called with logging already initialized", LOG_CRIT);
    return -1;
  }
  else
  {
    strcpy(log_identity, log_name);
  }
  return 0;
}

/*
Function is used to generate a unique string used as a filename for incomming mail.
unique_file_name_buffer should be 86 bytes for full encode of the 64 byte hash
(4/3 * 64) = 85.333
@param Salt used to mix up the hashing.
@param Pointer to a buffer where the unique file name will be written.
@return Length of the string written to unique_file_name_buffer
*/
int generate_unique_string(int salt, char * unique_file_name_buffer)
{
  struct timespec time_used_in_string_creation;
  clock_gettime(CLOCK_REALTIME, &time_used_in_string_creation);
  char meat_and_potatoes[24];
  memset(meat_and_potatoes, 0, sizeof(meat_and_potatoes));
  memcpy(meat_and_potatoes, &time_used_in_string_creation.tv_sec, sizeof(time_used_in_string_creation.tv_sec));
  memcpy(meat_and_potatoes+sizeof(time_used_in_string_creation.tv_sec), &salt, sizeof(salt));
  memcpy(meat_and_potatoes+sizeof(time_used_in_string_creation.tv_sec)+sizeof(salt), &time_used_in_string_creation.tv_nsec, sizeof(time_used_in_string_creation.tv_nsec));
  unsigned char hash[64]; //64 bytes because hash has a fixed size output
  crypto_generichash(hash, sizeof(hash), (const unsigned char *)meat_and_potatoes, sizeof(meat_and_potatoes),NULL, 0);
  int unique_file_name_length = base64_encode((char *)hash, sizeof(hash), unique_file_name_buffer, sizeof(unique_file_name_buffer), (char *)filesystem_safe_base64_string, 64);
  return unique_file_name_length;
}

/*
Simple interface to syslog
@param String to be sent to the log
@param Log level that syslog will tag it with. LOG_INFO, LOG_ERR, LOG_CRIT, LOG_EMERG, etc...
@return None.
*/
void print_to_log(char * message, int level)
{
  openlog(log_identity, LOG_PID, LOG_MAIL);
  syslog(level, message);
  closelog();
}

/*
Used to drop process privilage (though in theory it's more general than that). Should return -1 on failure, 0 otherwise.
Inspired/informed by http://www.cs.berkeley.edu/~daw/papers/setuid-usenix02.pdf
@param user to be used (c string). Group ID is derived from the user id.
@return 0 on success, -1 on failure.
*/
int set_privilage(char * new_user)
{
  struct passwd * working_user_passwd;
  working_user_passwd = getpwnam(new_user);
  print_to_log("Attempting to drop privilage", LOG_INFO);
  printf("working uid = %x, gid = %x, name = %s\n", working_user_passwd->pw_uid, working_user_passwd->pw_gid, working_user_passwd->pw_name);
  if (setresgid(working_user_passwd->pw_gid, working_user_passwd->pw_gid, working_user_passwd->pw_gid)<0)
  {
    perror("setresgid");
    print_to_log("Setresgid has failed. Cannot move to least privilage user.", LOG_EMERG);
    return -1;
  }
  if (setresuid(working_user_passwd->pw_uid, working_user_passwd->pw_uid, working_user_passwd->pw_uid)<0)
  {
    perror("setresuid");
    print_to_log("Setresuid has failed. Cannot move to least privilage user.", LOG_EMERG);
    return -1;
  }
  print_to_log("Process has successfully dropped privilage", LOG_INFO);
  return 0;
}

/*
Jail init function. Ensures that logging and DNS lookups will work from within the jail.
@return -1 on failure. 0 on success.
*/
int init_jail(char * jail_dir)
{
  //Move to directory so that setup can be done with relative paths
  if (chdir(jail_dir)<0)
  {
    perror("chdir");
    print_to_log("chdir failed. Cannot enter jail for setup.", LOG_EMERG);
    return -1;
  }
  print_to_log("Initializing cmtpd's jail.", LOG_INFO);
  create_verify_dir("etc");
  create_verify_dir("mail");
  if (access("etc/resolv.conf", R_OK)<0)
  {
    write_to_file(NULL, 0, "etc/resolv.conf");
    if(mount("/etc/resolv.conf", "etc/resolv.conf", 0, MS_BIND, 0)<0)
    {
      print_to_log("Cannot mount resolv.conf in jail.", LOG_EMERG);
      perror("First jail mount");
      return -1;
    }
  }
  create_verify_dir("dev");
  if (access("dev/log", R_OK|W_OK)<0)
  {
    write_to_file(NULL, 0, "dev/log");
    if(mount("/dev/log", "dev/log", 0, MS_BIND, 0)<0)
    {
      print_to_log("Cannot mount /dev/log in jail.", LOG_EMERG);
      perror("Second jail mount");
      return -1;
    }
  }

  //Move to a 'safe' directory before returning.
  if (chdir("/var")<0)
  {
    perror("chdir");
    print_to_log("chdir failed. Cannot move to /var after jail setup.", LOG_EMERG);
    return -1;
  }
  print_to_log("jail has been created without error.", LOG_INFO);
  return 0;
}

/*
Moves process into the jail directory
@param Character string denoting the jails location in the file system.
@return -1 on failure, 0 on success.
*/
int enter_jail(char * jail_dir, char * new_user)
{
  //Set ownership of mail directory
  char mail_dir[255] = {0};
  if (snprintf(mail_dir, sizeof(mail_dir), "%s%s", jail_dir, "/mail")<0)
  {
    perror("enter_jail snprintf");
    print_to_log("Cannot create mail_dir string", LOG_ERR);
    return -1;
  }
  struct passwd * working_user_passwd;
  working_user_passwd = getpwnam(new_user);
  print_to_log("Attempting to drop privilage", LOG_INFO);
  printf("working uid = %x, gid = %x, name =%s\n", working_user_passwd->pw_uid, working_user_passwd->pw_gid, working_user_passwd->pw_name);
  if(chown(mail_dir, working_user_passwd->pw_uid, working_user_passwd->pw_gid)<0)
  {
    perror("chown");
    print_to_log("chown failed. Cannot gain write in jail.", LOG_EMERG);
    return -1;
  }
  if (chdir(jail_dir)<0)
  {
    perror("chdir");
    print_to_log("chdir failed. Cannot jail cmptd.", LOG_EMERG);
    return -1;
  }
  if (chroot(jail_dir)<0)
  {
    perror("chroot");
    print_to_log("chroot failed. Cannot jail cmptd.", LOG_EMERG);
    return -1;
  }
  if (setresgid(working_user_passwd->pw_gid, working_user_passwd->pw_gid, working_user_passwd->pw_gid)<0)
  {
    perror("setresgid");
    print_to_log("Setresgid has failed. Cannot move to least privilage user.", LOG_EMERG);
    return -1;
  }
  if (setresuid(working_user_passwd->pw_uid, working_user_passwd->pw_uid, working_user_passwd->pw_uid)<0)
  {
    perror("setresuid");
    print_to_log("Setresuid has failed. Cannot move to least privilage user.", LOG_EMERG);
    return -1;
  }
  print_to_log("Process has successfully dropped privilage", LOG_INFO);
  print_to_log("cmtp has entered its' jail.", LOG_INFO);
  return 0;
}


/*
* print_buffer
* Function taken from Edoardo Biagioni's Allnet project. Code was unlicensed at time of inclusion and verbal permission of use was obtained.
* Full project can be found here
* http://alnt.org/
*/
void print_buffer (const char * buffer, int count, char * desc,
                   int max, int print_eol)
{
  int i;
  if (desc != NULL)
    printf ("%s (%d bytes):", desc, count);
  else
    printf ("%d bytes:", count);
  if (buffer == NULL)
    printf ("(null)");
  else {
    for (i = 0; i < count && i < max; i++)
      printf (" %02x", buffer [i] & 0xff);
    if (i < count)
      printf (" ...");
  }
  if (print_eol)
    printf ("\n");
}

int32_t read_n_bytes(uint32_t socket, char * reception_buffer, uint64_t n)
{
	uint32_t received = 0;
  int64_t count = 0;
	do{
		count = read(socket, reception_buffer+received, 1);
    if (count<=0)
    {
      perror("read_n_bytes");
      print_to_log("Error reading in read_n_bytes", LOG_ERR);
      return -1;
    }
		received+=count;
		if (received==n)
		  {
        return received;
		  }
    } while(received<=n);
    return received;
}

int32_t read_until(uint32_t socket, char * reception_buffer, uint32_t reception_buffer_size, char terminator)
{
	uint32_t received = 0;
  int32_t count = 0;
	do{
		count = read(socket, reception_buffer+received, 1);
    if (count<=0)
    {
      perror("read_until");
      print_to_log("Error reading in read_until", LOG_ERR);
      return -1;
    }
		if (reception_buffer[received]==terminator)
		  {
        return received+1;
		  }
    received+=count;
    } while(received<=reception_buffer_size);
    memset(reception_buffer, 0, reception_buffer_size);
    return -1;
}

//Gets input from user. Removes trailing newline character.
uint32_t prompt_input_string(char * welcome, char * descriptor, char * storage, uint32_t storage_length)
{
  if (storage_length>256)
  {
    return -1;
  }
	char input[256] = {0};
	printf("%s%s\n", welcome, descriptor);
	if (fgets(input, sizeof(input), stdin)==NULL)
  {
    perror("fgets");
  }
	fseek(stdin,0,SEEK_END);
  if (strlen(input-1)<=storage_length)
  {
    memcpy(storage, input, strlen(input)-1);
  	return sizeof(storage);
  }
  memset(input, 0, 256);
  return -1;
}

int32_t cmtp_hash(uint32_t version, unsigned char * buffer_to_hash, uint32_t buffer_to_hash_length, unsigned char * salt, unsigned char * return_buffer, uint32_t return_buffer_length)
{
  if (version==1)
  {
    if (return_buffer_length!=32)
    {
      perror("return_buffer_length of incorrect size");
      print_to_log("return_buffer_length of incorrect size in cmtp_hash", LOG_ERR);
      return -1;
    }
    //do version 1 hash
    unsigned char * hash = calloc(1, 32);
    if (crypto_pwhash_scryptsalsa208sha256(hash, 32, buffer_to_hash, buffer_to_hash_length, salt, crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0)
    {
      perror("crypto_pwhash_scryptsalsa208sha256 error in cmtp_hash");
      print_to_log("crypto_pwhash_scryptsalsa208sha256 error in cmtp_hash", LOG_ERR);
      free(hash);
      return -1;
    }
    memcpy(return_buffer, hash, 32);
    free(hash);
    return 0;
  }
  //Incorrect version. Fail.
  return -1;
}
