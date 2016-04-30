#include <stdio.h>
#include <sodium.h>

int main (int argc, char * argv[])
{
  sodium_init();
  if (crypto_aead_aes256gcm_is_available() == 0) {
      printf("libsodium AES is not available on this CPU\n"); /* Not available on this CPU */
  }
  else
  {
    printf("libsodium AES is available on this CPU\n");  
  }
}
