#include <stdlib.h>
#include <string.h>
/* alloca stack overflow */
int main(int argc, char **argv) { int n=argc>1?atoi(argv[1]):64; char *b=alloca(n); memset(b,0,n+256); return 0; }