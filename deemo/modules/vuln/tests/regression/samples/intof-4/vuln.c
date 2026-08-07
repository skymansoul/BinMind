#include <stdlib.h>
int main() { size_t n=0x100000001; char*p=calloc(n,4); free(p); return 0; }
