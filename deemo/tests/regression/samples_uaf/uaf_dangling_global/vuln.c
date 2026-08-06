#include <stdio.h>
#include <stdlib.h>
char *g_buf = NULL;
void init() { g_buf = malloc(256); }
void cleanup() { free(g_buf); }
int main() { init(); cleanup(); puts(g_buf); return 0; }
