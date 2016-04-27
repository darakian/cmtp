#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include "cmtp_common.h"

int main(int argc, char * argv[])
{
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
  char yes_no[3] = {0};
  printf("Create cmtp user %s?\n", argv[1]);
  prompt_input_string("y/n: ", " ", yes_no, 1);
  #ifdef DEBUG
  printf("Attempting to create user %s in /var/cmtp\n", argv[1]);
  #endif /*DEBUG*/
  if (access())
}
