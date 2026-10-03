#include <string.h>
/* Stack overflow via nested call */
void inner(char *s) { char b[32]; strcpy(b,s); }
void outer(char *s) { inner(s); }
int main(int argc, char **argv) { if(argc>1) outer(argv[1]); return 0; }