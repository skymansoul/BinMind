#include <stdio.h>
#include <string.h>
void parse_splt(char*d,int len){char buf[256];memcpy(buf,d,len>256?256:len);buf[255]=0;printf("%s",buf);}
int main(int c,char**v){char d[512];memset(d, 'A', 512);parse_splt(d,512);return 0;}