#include <stdlib.h>
void n(unsigned c){unsigned sz=c<<2;if(sz<c)return;char*b=malloc(sz);free(b);}
int main(int c,char**v){n(c>1?atoi(v[1]):0x40000000);return 0;}