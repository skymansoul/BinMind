#include <stdlib.h>
void f(unsigned n,unsigned s){char*b=malloc(n*s);b[0]=0;free(b);}
int main(int c,char**v){f(c>1?atoi(v[1]):0x80000001,4);return 0;}