#include <stdio.h>
#include <string.h>
/* Indirect format string via wrapper */
void wrapper(const char *s) { printf(s); }
int main(int argc, char **argv) { if(argc>1) wrapper(argv[1]); return 0; }