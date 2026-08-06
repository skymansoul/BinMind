#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void copy(char *s,int x){int sz=strlen(s)+x;char *p=malloc(sz);memcpy(p,s,sz);free(p);}
int main(int c,char **v){if(c>2)copy(v[1],atoi(v[2]));return 0;}
