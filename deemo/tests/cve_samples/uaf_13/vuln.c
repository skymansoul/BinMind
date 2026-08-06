#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process() { char *p = malloc(64); free(p); puts(p); }
int main() { process(); return 0; }
