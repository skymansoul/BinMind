#include <stdio.h>
#include <string.h>
void parse_sudo_args(char*args){char buf[128];int l=strlen(args);memcpy(buf,args,l);buf[l]=0;printf("%s",buf);}
int main(int c,char**v){parse_sudo_args(v[1]?v[1]:"-u");return 0;}