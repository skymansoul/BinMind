#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int c,char**v) { if(c>1){char *m=malloc(strlen(v[1])+1);strcpy(m,v[1]);printf(m);free(m);} return 0; }
