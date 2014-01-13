#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  int i;
  //~ printf("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeecho.c: argc: %d\n", argc);
  for (i = 0; i < argc; i++)
    printf ("i:%d %s\n", i, argv[i]);
  printf ("RAN ONCE\n");

  return EXIT_SUCCESS;
}
