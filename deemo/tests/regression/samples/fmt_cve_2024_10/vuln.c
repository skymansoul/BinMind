/* FMT: fprintf stderr with user fmt */
#include <stdio.h>
int main(int argc, char **argv) { if(argc>1) fprintf(stderr, argv[1]); return 0; }
