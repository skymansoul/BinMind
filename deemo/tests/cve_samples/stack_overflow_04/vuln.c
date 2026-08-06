#include <stdio.h>
#include <stdlib.h>
void recurse(int depth, char *buf) { char local[4096]; if (depth > 0) recurse(depth-1, local); }
int main(int argc, char **argv) { int d = argc > 1 ? atoi(argv[1]) : 100; recurse(d, NULL); return 0; }
