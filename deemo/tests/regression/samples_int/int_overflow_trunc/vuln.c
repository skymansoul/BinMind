#include <stdio.h>
#include <stdlib.h>
void truncate(unsigned long long n){unsigned sz=(unsigned)n;char *p=malloc(sz);free(p);}
int main(){truncate(0x100000001ULL);return 0;}
