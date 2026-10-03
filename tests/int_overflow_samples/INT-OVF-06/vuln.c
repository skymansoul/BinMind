#include <stdlib.h>
void safe_mul(unsigned n){unsigned sz=n*8;if(sz<n)return;char*b=malloc(sz);free(b);}
int main(int c,char**v){safe_mul(c>1?atoi(v[1]):0x20000001);return 0;}