#include <stdio.h>
#include <stdlib.h>
char *shared = NULL;
void do_free() { free(shared); }
int main() { shared = malloc(128); do_free(); free(shared); return 0; }
