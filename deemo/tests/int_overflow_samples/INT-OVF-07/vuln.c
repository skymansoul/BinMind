#include <stdlib.h>
void wrapped(unsigned x){unsigned a=x+0xFFFF;char*b=malloc(a);free(b);}
int main(int c,char**v){wrapped(c>1?atoi(v[1]):0xFFFF0001);return 0;}