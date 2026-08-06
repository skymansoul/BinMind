#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void alloc_streams(int n){char*b=malloc(n*16);memset(b,0,n*16);printf("allocd %d",n);free(b);}
int main(int c,char**v){alloc_streams(c>1?atoi(v[1]):100);return 0;}