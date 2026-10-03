/* FMT: format via function pointer */
#include <stdio.h>
int main(int argc, char **argv) { int (*printer)(const char*,...) = printf; if(argc>1) printer(argv[1]); return 0; }
