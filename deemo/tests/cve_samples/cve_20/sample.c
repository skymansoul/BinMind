#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void parse_xml(char*xml,int xl){char*b=malloc(xl);memcpy(b,xml,xl+1);printf("%s",b);free(b);}
int main(int c,char**v){parse_xml(v[1]?v[1]:"<root/>",c>1?strlen(v[1]):7);return 0;}