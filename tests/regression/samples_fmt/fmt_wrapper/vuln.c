#include <stdio.h>
void debug(const char *f) { printf(f); }
int main(int argc, char **argv) { if(argc<2)return 1;
debug(argv[1]); return 0; }
