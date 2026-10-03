#include <stdio.h>
#include <string.h>
void process_sack(char*opts,int olen){char sack[128];memcpy(sack,opts,olen);printf("%s",sack);}
int main(){char o[256];memset(o,0x53,256);process_sack(o,256);return 0;}