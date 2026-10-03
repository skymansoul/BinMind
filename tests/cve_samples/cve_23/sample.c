#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void decode_frame(char*f,int fl){char*b=malloc(fl-16);memcpy(b,f,fl);printf("%s",b);free(b);}
int main(int c,char**v){char f[512];memset(f,0xFF,512);decode_frame(f,512);return 0;}