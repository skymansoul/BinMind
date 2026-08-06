#include <stdlib.h>
#include <string.h>
void h(int n){int sz=n*sizeof(void*);char*b=malloc(sz);memset(b,0,sz);free(b);}
int main(int c,char**v){h(c>1?atoi(v[1]):0x40000000);return 0;}