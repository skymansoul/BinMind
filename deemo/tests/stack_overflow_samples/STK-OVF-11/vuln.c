#include <stdlib.h>
void alloca_flow(unsigned n){char*d=alloca(n);d[0]=0;}
int main(int c,char**v){alloca_flow(c>1?atoi(v[1]):99999);return 0;}