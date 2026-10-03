#include <stdlib.h>
int main() { unsigned short s=65535; s++; char*p=malloc(s); free(p); return 0; }
