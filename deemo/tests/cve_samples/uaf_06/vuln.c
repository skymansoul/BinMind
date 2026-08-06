#include <stdio.h>
#include <stdlib.h>
char *ptr = NULL;
void do_work() { ptr = malloc(128); free(ptr); puts(ptr); }
int main() { do_work(); return 0; }
