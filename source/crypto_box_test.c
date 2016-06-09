#include <stdio.h>
#include <sodium.h>

int main(int argc, char * argv[])
{
  char body[] = "This is some text to encrypt";
  int message_length = sizeof(body)+crypto_box_SEALBYTES;
  char * encrypted_message_body = calloc(1, message_length);
	char * plain_message_body = calloc(1, message_length-crypto_box_SEALBYTES);
  unsigned char user_publickey[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char user_secretkey[crypto_sign_ed25519_SECRETKEYBYTES];
  crypto_sign_ed25519_keypair(user_publickey, user_secretkey);

  //Use Ed keys to generate Box keys
  unsigned	char	curve25519_pk[crypto_scalarmult_curve25519_BYTES];
  unsigned	char	curve25519_sk[crypto_scalarmult_curve25519_BYTES];
  crypto_sign_ed25519_pk_to_curve25519(curve25519_pk,	user_publickey);
  crypto_sign_ed25519_sk_to_curve25519(curve25519_sk,	user_secretkey);

  if (crypto_box_seal(encrypted_message_body, body, sizeof(body), curve25519_pk)!=0)
  {
    perror("crypto_box_seal");
    return -1;
  }
  if (crypto_box_seal_open(plain_message_body, encrypted_message_body, message_length, curve25519_pk, curve25519_sk) != 0)
	{
    perror("crypto_box_seal_open");
		return -1;
	}
  for (int i =0; i<sizeof(body); i++)
  {
    printf("%c", plain_message_body[i]);
  }
}
