#include <stdio.h>
#include <string.h>
void load_elf_header(char*data,int len){char hdr[128];memcpy(hdr,data,len<128?len:128);printf("%s",hdr);}
int main(){char d[256];memset(d,0x45,256);load_elf_header(d,256);return 0;}