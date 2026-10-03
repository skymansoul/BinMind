#include <stdlib.h>
void g(unsigned n){char*b=malloc(n+0xFFFFFFFF);b[0]=0;free(b);}
int main(int c,char**v){g(c>1?atoi(v[1]):100);return 0;}