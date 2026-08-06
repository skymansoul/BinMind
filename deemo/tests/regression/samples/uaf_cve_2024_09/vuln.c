/* UAF global ptr */
#include <stdio.h>
#include <stdlib.h>
static char *g_buf;
void release(void) { free(g_buf); }
void use(void) { puts(g_buf); }
int main() { g_buf=malloc(256); release(); use(); return 0; }
