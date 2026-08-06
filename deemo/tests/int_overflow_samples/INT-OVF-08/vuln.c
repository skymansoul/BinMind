#include <stdlib.h>
void shift_ovf(unsigned c){unsigned sz=1<<c;char*b=malloc(sz);free(b);}
int main(int c,char**v){shift_ovf(c>1?atoi(v[1]):32);return 0;}