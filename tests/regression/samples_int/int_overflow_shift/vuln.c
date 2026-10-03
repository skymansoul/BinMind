#include <stdio.h>
#include <stdlib.h>
void table(int n){int sz=1<<n;char *p=malloc(sz);free(p);}
int main(int c,char **v){if(c>1)table(atoi(v[1]));return 0;}
