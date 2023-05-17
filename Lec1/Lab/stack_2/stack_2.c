#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "c8763.c"

extern void c8763(void);
int main(int argc, char **argv)
{
  volatile int got_permissions;
  char buffer[64];

  got_permissions = 0;
  gets(buffer);

  if(got_permissions == 0xc8763) {
      c8763();
  } else {
      printf("Access Denied\n");
  }
}

