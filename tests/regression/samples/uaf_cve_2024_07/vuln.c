/* UAF realloc zero */
#include <stdio.h>
#include <stdlib.h>
int main() { char *buf=malloc(256); realloc(buf,0); puts(buf); return 0; }
