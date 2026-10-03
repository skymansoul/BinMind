#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() { char *p = malloc(64); strcpy(p, "original");
char *q = realloc(p, 128); strcpy(p, "stale"); free(q); return 0; }
