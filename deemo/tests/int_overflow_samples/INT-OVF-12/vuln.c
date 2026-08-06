#include <stdlib.h>
void j(size_t n,size_t m){char*b=calloc(n,m);b[0]=0;free(b);}
int main(int c,char**v){j(c>1?atol(v[1]):0x100000000,8);return 0;}