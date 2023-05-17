#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int got_permissions;
  char buffer[64];

  got_permissions = 0;
  gets(buffer);

  if(got_permissions != 0) {
      printf("Access Acept, Welcome to HackerSir\n");
  } else {
      printf("Access Denied\n");
  }
}