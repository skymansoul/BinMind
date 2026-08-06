#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void buf_copy(char *s){int l=strlen(s);char *b=malloc(l);strcpy(b,s);free(b);}
int main(int c,char **v){if(c>1)buf_copy(v[1]);return 0;}
