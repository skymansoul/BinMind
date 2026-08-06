/* FMT: dprintf */
#include <stdio.h>
int main(int argc, char **argv) { if(argc>1) dprintf(1, argv[1]); return 0; }
