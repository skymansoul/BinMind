#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void f(int n, const char *s) { char buf[n]; strcpy(buf, s); }
int main(int argc, char **argv) { f(argc>1?atoi(argv[1]):16, argc>2?argv[2]:""); return 0; }
