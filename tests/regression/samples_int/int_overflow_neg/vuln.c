#include <stdio.h>
#include <stdlib.h>
void do_alloc(int n){if(n<0)n=0;char *p=malloc(n);free(p);}
int main(int c,char **v){if(c>1)do_alloc(atoi(v[1]));return 0;}
