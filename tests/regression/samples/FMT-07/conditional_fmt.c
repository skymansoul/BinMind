#include <stdio.h>
/* Conditional format string */
int main(int argc, char **argv) { char *fmt="%s"; if(argc>1) fmt=argv[1]; printf(fmt, "test"); return 0; }