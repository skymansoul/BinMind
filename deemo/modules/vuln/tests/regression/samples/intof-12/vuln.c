#include <stdlib.h>
int main() { size_t sz=0x100000001;unsigned n=(unsigned)sz;char*p=malloc(n);free(p);return 0;}
