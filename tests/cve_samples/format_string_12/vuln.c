#include <stdio.h>
int main(int argc, char **argv) { fprintf(stderr, argc>1?argv[1]:"log"); return 0; }
