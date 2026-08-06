/* UAF worker pattern */
#include <stdio.h>
#include <stdlib.h>
static char *shared;
void worker_free(void) { free(shared); }
int main() { shared=malloc(128); worker_free(); puts(shared); return 0; }
