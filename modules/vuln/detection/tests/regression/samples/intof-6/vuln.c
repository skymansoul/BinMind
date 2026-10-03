#include <stdlib.h>
int main() { int idx=0x7FFFFFFF; idx+=10; char*p=malloc(256); p[idx]=0; free(p); return 0; }
