#include <stdlib.h>
void j(size_t n){char*b=calloc(n,8);b[0]=0;free(b);}
int main(int c,char**v){j(c>1?atol(v[1]):0x2000000000000001);return 0;}