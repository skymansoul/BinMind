#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void resolve_host(char*name){char tmp[256];int nl=strlen(name);memcpy(tmp,name,nl);tmp[nl]=0;printf("%s",tmp);}
int main(int c,char**v){resolve_host(v[1]?v[1]:"localhost");return 0;}