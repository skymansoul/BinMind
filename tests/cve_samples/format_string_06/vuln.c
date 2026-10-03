#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) { fprintf(stderr, argc>1?argv[1]:"%%s"); return 0; }
