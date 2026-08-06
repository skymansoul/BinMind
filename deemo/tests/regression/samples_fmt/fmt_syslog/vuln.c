#include <stdio.h>
void log_it(const char *s) { printf(s); }
int main(int argc, char **argv) { if(argc<2)return 1;
log_it(argv[1]); return 0; }
