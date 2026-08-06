#include <stdlib.h>
void g(int n){char*b=malloc(n*sizeof(int));b[0]=0;free(b);}
int main(int c,char**v){g(c>1?atoi(v[1]):0x40000001);return 0;}