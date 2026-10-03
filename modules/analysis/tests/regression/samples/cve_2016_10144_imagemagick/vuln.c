#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(){char *b=malloc(128);char d[512];memset(d,0x44,512);memcpy(b,d,512);free(b);return 0;}