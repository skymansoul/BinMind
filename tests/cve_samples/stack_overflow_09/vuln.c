#include <stdio.h>
#include <stdlib.h>
void deep(int n, char *p) { char local[1024]; if(n) deep(n-1, local); }
int main(int argc, char **argv) { deep(argc>1?atoi(argv[1]):100, 0); return 0; }
