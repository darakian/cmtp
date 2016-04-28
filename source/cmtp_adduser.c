#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sodium.h>
#include <endian.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "cmtp_common.h"

int main(int argc, char * argv[])
{
  sodium_init();
  char yes_no[3] = {0};
  char user_path[256+15] = {0};
  char user_publickey_path[256+15+10] = {0};
  char user_privatekey_path[256+15+10] = {0};
  char user_password[256] = {0};
  int temp_descriptor = -1;
  char user_password_hash[crypto_aead_aes256gcm_KEYBYTES] = {0}; //size = 32

  if (argc<=1)
  {
    /*Interactive mode. To be done later.*/
    printf("Interactive mode not yet working :(\n");
    return 0;
  }
  if (argc>=3)
  {
    printf("Usage: cmtp_adduser <username>\n");
  }

  printf("Create cmtp user %s?\n", argv[1]);
  prompt_input_string("y/n: ", " ", yes_no, sizeof(yes_no));
  prompt_input_string("Password please: ", " ", user_password, sizeof(user_password));
  #ifdef DEBUG
  printf("Attempting to create user %s in /var/cmtp/mail/\n", argv[1]);
  //printf("crypto_pwhash_SALTBYTES = %d\n", crypto_pwhash_SALTBYTES);

  #endif /*DEBUG*/
  if (snprintf(user_path, sizeof(user_path), "%s%s", "/var/cmtp/mail/", argv[1])<0)
  {
    perror("snprintf");
    return -1;
  }
  if (snprintf(user_publickey_path, sizeof(user_publickey_path), "%s%s%s", "/var/cmtp/mail/", argv[1], "public.key")<0)
  {
    perror("snprintf");
    return -1;
  }
  if (access(user_path, R_OK)>=0)
  {
    printf("User %s directory already exists at %s\n", argv[1], user_path);
    return -1;
  }
  if (create_verify_dir(user_path)<0)
  {
    perror("create_verify_dir");
    return -1;
  }
  unsigned char user_publickey[crypto_box_PUBLICKEYBYTES];
  unsigned char user_secretkey[crypto_box_SECRETKEYBYTES];
  crypto_box_keypair(user_publickey, user_secretkey);
  if ((temp_descriptor=open(user_publickey_path, O_WRONLY|O_CREAT, S_IRUSR|S_IRGRP|S_IROTH))<0)
  {
    perror("open");
    printf("Cannot write out user public key. Exiting.\n");
    return -1;
  }
  if (write(temp_descriptor, user_publickey, sizeof(user_publickey))<0)
  {
    perror("write");
    printf("Write of public key failed. Exiting.\n");
    return -1;
  }
  if (close(temp_descriptor)<0)
  {
    perror("close");
    printf("close has failed. Exiting.\n");
    return -1;
  }
  //Create xzibit


}
