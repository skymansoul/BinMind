#include <stdio.h>
/* sprintf with user fmt */
int main(int argc, char **argv) { char b[256]; if(argc>1) sprintf(b, argv[1]); return 0; }