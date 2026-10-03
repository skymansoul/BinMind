#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void decode_image(char*d,int dl){char*buf=malloc(1024);memcpy(buf,d,dl);printf("%s",buf);free(buf);}
int main(int c,char**v){char d[2048];memset(d,0x42,2048);decode_image(d,2048);return 0;}