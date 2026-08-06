#include <stdio.h>
/* err() with format from argv */
void err(int eval, const char *fmt, ...);
int main(int argc, char **argv) { if(argc>1) err(1, argv[1]); return 0; }