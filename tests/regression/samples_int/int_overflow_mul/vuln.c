#include <stdio.h>
#include <stdlib.h>
void alloc(int n) { int sz=n*1024; char *p=malloc(sz); free(p); }
int main(int c,char **v){if(c>1)alloc(atoi(v[1]));return 0;}
