#include <stdio.h>
#include <string.h>
/* Nested format string */
void inner(const char *s) { printf(s); }
void outer(const char *s) { inner(s); }
int main(int argc, char **argv) { if(argc>1) outer(argv[1]); return 0; }