#include <stdlib.h>
void f(unsigned a,unsigned b){char*p=malloc(a+b);p[0]=0;free(p);}
int main(int c,char**v){f(c>1?atoi(v[1]):0xFFFF0000,0xFFFF);return 0;}