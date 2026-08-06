/* UAF + info leak via uninitialized heap read / CWE-416 + CWE-125 */
#include <stdlib.h>
#include <string.h>
static char *g_buf = NULL;
void process(int sz) {
    g_buf = malloc(sz);
    free(g_buf); /* g_buf dangling */
    char leak = g_buf[0]; /* UAF read */
}
int main(void) { process(64); return 0; }
