#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process(unsigned long long n){int sz=(int)n;char *p=malloc(sz);memset(p,0,(size_t)n);free(p);}
int main(){process(0x100000000ULL);return 0;}
