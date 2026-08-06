#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(){char *b=malloc(64);char d[256];memset(d,0x41,256);memcpy(b,d,200);free(b);return 0;}