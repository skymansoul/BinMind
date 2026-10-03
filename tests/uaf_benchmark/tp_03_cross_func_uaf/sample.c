/* TP-03: Cross-Function UAF (CWE-416) */
#include <stdlib.h>
#include <stdio.h>
static char *g_buf = NULL;
void alloc_buf(void) { g_buf = (char *)malloc(256); }
void free_buf(void) { if (g_buf) { free(g_buf); } }
void cross_uaf(void) {
    alloc_buf(); free_buf();
    printf("%c\n", g_buf[0]);  /* UAF */
}
int main(void) { cross_uaf(); return 0; }