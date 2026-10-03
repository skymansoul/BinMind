#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* CVE-2017-0561: Broadcom WiFi firmware heap overflow in event handler */
int main(){char *b=malloc(48);char d[256];memset(d,0x45,256);memcpy(b,d,256);free(b);return 0;}
