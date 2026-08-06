/* CVE-2014-3153 — Linux futex UAF via PI futex / CWE-416 */
#include <stdlib.h>
typedef struct { int key; void *data; } futex_t;
futex_t *g_ftx = NULL;
void futex_release(void) { free(g_ftx); /* g_ftx not NULL'd */ }
void futex_wait(void) {
    g_ftx = malloc(sizeof(futex_t));
    futex_release();
    if (g_ftx->key == 0) g_ftx->data = NULL; /* UAF */
}
int main(void) { futex_wait(); return 0; }
