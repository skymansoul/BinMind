/* FMT: write syscall with fmt from env */
#include <stdio.h>
#include <stdlib.h>
int main() { char *s = getenv("FORMAT"); if(s) printf(s); return 0; }
