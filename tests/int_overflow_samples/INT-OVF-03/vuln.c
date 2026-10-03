#include <stdlib.h>
void h(unsigned a,unsigned b){char*p=malloc(a*b+16);p[0]=0;free(p);}
int main(){h(0x80000001,2);return 0;}