#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void socks_resolve(char*h){int hl=strlen(h);char*b=malloc(256);memcpy(b,h,hl);b[hl]=0;printf("resolved: %s
",b);free(b);}
int main(int c,char**v){socks_resolve(v[1]?v[1]:"localhost");return 0;}