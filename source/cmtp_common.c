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

#include "../include/base64.h"
#include "cmtp_common.h"

static char log_identity[255];
static int loginit = 0;
static pthread_mutex_t dns_lock;

//const char filesystem_safe_base64_string[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_";

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


/*Return is of type int and is just the mx family type. Ohana is hawaiian for family*/
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
filename is expected to be a c string
*/
int write_to_file(char * buffer, int buffer_length, char * filename)
{
  // #ifdef DEBUG
  // printf("Entering write_to_file subroutine\n");
  // #endif /*DEBUG*/
  int file_description = open(filename, O_WRONLY|O_APPEND|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
  if ((file_description)<0)
  {
    perror("open");
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
path is expected to be a null terminated string
Function tries to create a directory and verifies that the directory is writable
Return -1 on error, 0 on sucess
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
  strcat(test_file, path);
  strcat(test_file, "/test");
  //Attempt to write a file to ensure writability
  int file_descriptor = (open(test_file, O_CREAT|O_RDWR, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH));
  if (file_descriptor== -1)
  {
    perror("open");
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


//unique_file_name_buffer should be 86 bytes for full encode of the 64 byte hash
//(4/3 * 64) = 85.333
int generate_unique_string(int salt, char * unique_file_name_buffer)
{
  struct timespec time_used_in_string_creation;
  clock_gettime(CLOCK_REALTIME, &time_used_in_string_creation);
  char meat_and_potatoes[24];
  memset(meat_and_potatoes, 0, sizeof(meat_and_potatoes));
  memcpy(&meat_and_potatoes, &time_used_in_string_creation.tv_sec, sizeof(time_used_in_string_creation.tv_sec));
  memcpy(&meat_and_potatoes+sizeof(time_used_in_string_creation.tv_sec), &salt, sizeof(salt));
  memcpy(&meat_and_potatoes+sizeof(time_used_in_string_creation.tv_sec)+sizeof(salt), &time_used_in_string_creation.tv_nsec, sizeof(time_used_in_string_creation.tv_nsec));
  unsigned char hash[64]; //64 bytes because hash has a fixed size output
  crypto_generichash(hash, sizeof(hash), (const unsigned char *)meat_and_potatoes, sizeof(meat_and_potatoes),NULL, 0);
  int unique_file_name_length = base64_encode((char *)hash, sizeof(hash), unique_file_name_buffer, sizeof(unique_file_name_buffer), (char *)filesystem_safe_base64_string, 64);
  return unique_file_name_length;
}

//Used to simplify printing to system log
void print_to_log(char * message, int level)
{
  openlog(log_identity, LOG_PID, LOG_MAIL);
  syslog(level, message);
  closelog();
}


//Used to drop process privilage (though in theory it's more general than that). Should return -1 on failure, 0 otherwise.
//Inspired/informed by http://www.cs.berkeley.edu/~daw/papers/setuid-usenix02.pdf
int set_privilage(uid_t new_uid, gid_t new_gid)
{
  if (setresgid(new_gid, new_gid, new_gid)<0)
  {
    perror("setresgid");
    print_to_log("Setresgid has failed. Cannot move to least privilage user.", LOG_EMERG);
    return -1;
  }
  if (setresuid(new_uid, new_uid, new_uid)<0)
  {
    perror("setresuid");
    print_to_log("Setresuid has failed. Cannot move to least privilage user.", LOG_EMERG);
    return -1;
  }
  return 0;
}
