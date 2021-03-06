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
const uint32_t crypto_version = 1;
uint32_t network_crypto_version = 0;

int main(int argc, char * argv[])
{
  sodium_init();
  network_crypto_version = htobe32(crypto_version);
  char yes_no[3] = {0};
  char user_path[256+15] = {0};
  char user_publickey_path[256+15+10] = {0};
  char user_xzibit_path[256+15+10] = {0};
  char user_password[256] = {0};
  int temp_descriptor = -1;

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
  if (chmod(user_path, S_IWUSR|S_IRUSR|S_IXUSR|S_IWGRP|S_IRGRP|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH)<0)
  {
    perror("chmod");
    return -1;
  }
  if (chown(user_path, "nobody", "nobody")<0)
  {
    perror("chown");
    return -1;
  }
  unsigned char user_publickey[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char user_secretkey[crypto_sign_ed25519_SECRETKEYBYTES];
  crypto_sign_ed25519_keypair(user_publickey, user_secretkey);
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
  unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
  unsigned char salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
  unsigned char key[KEY_LEN];
  randombytes_buf(salt, sizeof(salt));
  memcpy(nonce, salt, sizeof(nonce));
  //Using scrypt here. Switch to argon2 when available
  if (crypto_pwhash_scryptsalsa208sha256(key, sizeof(key), user_password, strlen(user_password), salt, crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0)
  {
    perror("crypto_pwhash_scryptsalsa208sha256");
  }
  #ifdef DEBUG
  // print_buffer(user_secretkey, sizeof(user_secretkey), "user_secretkey", 64, 1);
  printf("End password hash\n");
  // print_buffer(nonce, sizeof(nonce), "nonce", 12, 1);
  #endif /*DEBUG*/

  //Symetric cipher with hashed user_password
  unsigned char ciphertext[sizeof(user_publickey)+sizeof(user_secretkey)+crypto_aead_chacha20poly1305_ABYTES] = {0};
  #ifdef DEBUG
  printf("Ciphertext length = %ld, private key length = %ld, public key length = %ld\n", sizeof(ciphertext), sizeof(user_secretkey), sizeof(user_publickey));
  #endif /*DEBUG*/
  uint64_t ciphertext_length = sizeof(ciphertext);
  uint64_t be_ciphertext_length = htobe64(ciphertext_length);
  unsigned char keys[sizeof(user_publickey)+sizeof(user_secretkey)] = {0};
  memcpy(keys, user_publickey, sizeof(user_publickey));
  memcpy(keys+sizeof(user_publickey), user_secretkey, sizeof(user_secretkey));
  if (crypto_aead_chacha20poly1305_encrypt(ciphertext, &ciphertext_length, keys, sizeof(keys), NULL, 0, NULL, nonce, key)<0)
  {
    perror("crypto_aead_chacha20poly1305_encrypt");
  }
  //Need to append the version, salt and length information to xzibit here
  uint64_t xzibit_length = ciphertext_length+32+4+8;
  unsigned char * xzibit = calloc(1, xzibit_length);
  memcpy(xzibit, &network_crypto_version, sizeof(network_crypto_version));
  memcpy(xzibit+sizeof(network_crypto_version), salt, sizeof(salt));
  memcpy(xzibit+sizeof(network_crypto_version)+sizeof(salt), &be_ciphertext_length, sizeof(be_ciphertext_length));
  memcpy(xzibit+sizeof(network_crypto_version)+sizeof(salt)+sizeof(ciphertext_length), ciphertext, sizeof(ciphertext));
  if (snprintf(user_xzibit_path, sizeof(user_xzibit_path), "%s%s%s%s%s", "/var/cmtp/mail/", argv[1], "/", argv[1], ".xzibit")<0)
  {
    perror("snprintf");
    return -1;
  }
  if ((temp_descriptor=open(user_xzibit_path, O_WRONLY|O_CREAT, S_IRUSR|S_IRGRP|S_IROTH))<0)
  {
    perror("open");
    printf("Cannot write out user public key. Exiting.\n");
    free(xzibit);
    return -1;
  }
  if (write(temp_descriptor, xzibit, xzibit_length)<0)
  {
    perror("write");
    printf("Write of xzibit failed. Exiting.\n");
    free(xzibit);
    return -1;
  }
  if (close(temp_descriptor)<0)
  {
    perror("close");
    printf("close has failed. Exiting.\n");
    free(xzibit);
    return -1;
  }
  free(xzibit);
}
