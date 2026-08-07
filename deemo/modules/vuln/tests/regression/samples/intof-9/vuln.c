#include <stdlib.h>
int main() { size_t s=0xFFFFFFFF; s=(s+15)&~15; char*p=malloc(s); free(p); return 0; }
