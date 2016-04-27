#include "cmtp_common.h"

int main(int argc, char * argv[])
{
  if (argc<=1)
  {
    /*Interactive mode*/
    return 0;
  }
  if (argc>=3)
  {
    //Too many arguments
    printf("Usage: cmtp_adduser <username>\n");
  }
}
