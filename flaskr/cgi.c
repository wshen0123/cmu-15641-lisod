#include <stdio.h>

int main()
{
  char buf[1000] = "\0";

  read(0, buf, 1000);

  printf("%s", buf);

  return 0;
}
