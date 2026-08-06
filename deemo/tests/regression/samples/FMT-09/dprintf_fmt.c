#include <stdio.h>
/* dprintf with user fmt */
int main(int argc, char **argv) { if(argc>1) dprintf(2, argv[1]); return 0; }