#include <stdio.h>
#include <string.h>
void tls_process(char*payload,int plen){char buf[64];if(plen>64)plen=64;memcpy(buf,payload,plen);printf("%s",buf);}
int main(int c,char**v){char p[256];memset(p, 0x42, 256);tls_process(p,256);return 0;}