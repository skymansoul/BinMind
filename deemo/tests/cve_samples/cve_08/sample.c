#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void parse(const unsigned char*p,unsigned int pl){
  char hdr[64],pay[256];
  unsigned int off;
  if(pl<8)return;
  off=(p[4]<<8)|p[5];
  memcpy(hdr,p,8);hdr[8]=0;
  unsigned int payl=pl-off; /* BUG: can underflow */
  memcpy(pay,p+off,payl<256?payl:255); /* overflow */
  pay[payl<256?payl:255]=0;
  printf("pay:%s\n",pay);
}
int main(int c,char**v){
  unsigned char p[512];memset(p,0x41,512);p[4]=0;p[5]=8;
  parse(p,512);
  return 0;
}
