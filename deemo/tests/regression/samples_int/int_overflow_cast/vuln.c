#include <stdio.h>
#include <stdlib.h>
void process(size_t n){int sz=(int)n;char *p=malloc(sz);memset(p,0,n);free(p);}
int main(){process(0x100000000ULL);return 0;}
