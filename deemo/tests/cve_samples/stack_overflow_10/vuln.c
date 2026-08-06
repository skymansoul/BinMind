/* stack_overflow_10 ¡ª alloca¿É±ä·ÖÅä */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) { int s=argc>1?atoi(argv[1]):1024; char *p=alloca(s); memset(p,0,s*2); return 0; }
