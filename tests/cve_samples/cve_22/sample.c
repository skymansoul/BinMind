#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void resolve_dns(char*q,int ql){char*b=malloc(512);memcpy(b,q,ql);printf("%s",b);free(b);}
int main(int c,char**v){resolve_dns(v[1]?v[1]:"google.com",c>1?strlen(v[1]):10);return 0;}