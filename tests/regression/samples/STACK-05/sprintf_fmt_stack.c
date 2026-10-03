#include <stdio.h>
/* sprintf format stack overflow */
int main(int argc, char **argv) { char b[64]; if(argc>1) sprintf(b,argv[1]); return 0; }