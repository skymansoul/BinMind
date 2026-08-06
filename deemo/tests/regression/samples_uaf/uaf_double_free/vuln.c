#include <stdio.h>
#include <stdlib.h>
void cleanup(char *p) { if (p) free(p); }
int main() { char *buf = malloc(128); cleanup(buf); free(buf); return 0; }
