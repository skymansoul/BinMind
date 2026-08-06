#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(){char *b=malloc(32);char d[128];memset(d,0x43,128);memcpy(b,d,128);free(b);return 0;}