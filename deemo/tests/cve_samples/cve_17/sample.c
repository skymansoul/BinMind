#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void decode_email(char*e){int l=strlen(e);char*d=malloc(l*2);int i2=0;for(int i=0;i<l;i++){if(e[i]==64){d[i2++]=e[i];continue;}d[i2++]=e[i];}d[i2]=0;printf("decoded: %s
",d);free(d);}
int main(int c,char**v){decode_email(v[1]?v[1]:"user@domain");return 0;}