#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char hb[64]="secret_key_material";
void tls_heartbeat(unsigned char*r,unsigned int rl){
  unsigned char resp[80];
  unsigned int pl;
  if(rl<3)return;
  pl=(r[1]<<8)|r[2]; /* BUG: attacker-controlled, not validated */
  memcpy(resp,hb,pl<80?pl:80);
  printf("heartbeat: %u bytes\n",pl);
}
int main(int c,char**v){
  unsigned char r[3]={0x01,0xFF,0xFF};
  tls_heartbeat(r,3);
  return 0;
}
