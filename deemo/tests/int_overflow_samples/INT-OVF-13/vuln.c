#include <stdlib.h>
void k(unsigned x,unsigned y){unsigned z=x*y;if(z<x)return;char*b=malloc(z);free(b);}
int main(int c,char**v){k(c>1?atoi(v[1]):0x8001,0x10001);return 0;}