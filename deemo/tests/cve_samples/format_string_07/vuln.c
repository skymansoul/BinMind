#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) { fprintf(stderr, "error: "); fprintf(stderr, argc>1?argv[1]:"unknown"); return 1; }
