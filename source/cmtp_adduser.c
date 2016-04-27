#include "cmtp_common.h"

int main(int argc, char * argv[])
{
  if (argc<=1)
  {
    /*Interactive mode. To be done later.*/
    return 0;
  }
  if (argc>=3)
  {
    printf("Usage: cmtp_adduser <username>\n");
  }

  printf("Create cmtp user %s?\n", argv[1]);

}
