#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sodium.h>
#include <endian.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "cmtp_common.h"
#define KEY_LEN 32

int main(int argc, char * argv[])
{
  sodium_init();
  char yes_no[3] = {0};
  char user_path[256+15] = {0};
  char user_publickey_path[256+15+10] = {0};
  char user_xzibit_path[256+15+10] = {0};
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
  if ((strcmp(yes_no, "n")==0)||(strcmp(yes_no,"no")==0))
  {
    return 0;
  }
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
  if (snprintf(user_publickey_path, sizeof(user_publickey_path), "%s%s%s", "/var/cmtp/mail/", argv[1], "/public.key")<0)
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
  unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
  unsigned char salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
  unsigned char key[KEY_LEN];

  randombytes_buf(nonce, sizeof nonce);
  randombytes_buf(salt, sizeof salt);
  if (crypto_pwhash_scryptsalsa208sha256(key, sizeof(key), user_password, strlen(user_password), salt, crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0)
  {
    perror("crypto_pwhash_scryptsalsa208sha256");
  }
  #ifdef DEBUG
  printf("Password hash:\n");
  for (int i=0; i<32;i++)
  {
    printf("%x", key[i]);
  }
  printf("\n");
  printf("End password hash\n");
  #endif /*DEBUG*/

  //Symetric cipher with hashed user_password
  unsigned char ciphertext[sizeof(user_publickey)+sizeof(user_secretkey)+crypto_aead_aes256gcm_ABYTES];
  printf("Here\n");
  unsigned char xzibit[sizeof(ciphertext+4)];
  printf("Here\n");
  if (crypto_aead_aes256gcm_encrypt(ciphertext,sizeof(ciphertext), xzibit, sizeof(xzibit), NULL, 0, NULL, nonce, key)<0)
  {
    perror("crypto_aead_aes256gcm_encrypt");
  }
  printf("Here\n");
  //Need to append the version and other envelope information to xzibit here

  if (snprintf(user_xzibit_path, sizeof(user_xzibit_path), "%s%s%s%s%s", "/var/cmtp/mail/", argv[1], "/", argv[1], ".xzibit")<0)
  {
    perror("snprintf");
    return -1;
  }
  if ((temp_descriptor=open(user_xzibit_path, O_WRONLY|O_CREAT, S_IRUSR|S_IRGRP|S_IROTH))<0)
  {
    perror("open");
    printf("Cannot write out user public key. Exiting.\n");
    return -1;
  }
  if (write(temp_descriptor, xzibit, sizeof(xzibit))<0)
  {
    perror("write");
    printf("Write of xzibit failed. Exiting.\n");
    return -1;
  }
  if (close(temp_descriptor)<0)
  {
    perror("close");
    printf("close has failed. Exiting.\n");
    return -1;
  }



}
