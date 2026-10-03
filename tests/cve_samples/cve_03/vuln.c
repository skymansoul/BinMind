/* UAF sample 03 — Use-After-Free via dangling global pointer / CWE-416 */
#include <stdlib.h>
#include <string.h>
typedef struct { int id; char *buf; } obj_t;
static obj_t *g_obj = NULL;
void release(void) { free(g_obj->buf); free(g_obj); /* dangling */ }
void trigger(void) {
    g_obj = malloc(sizeof(obj_t)); g_obj->buf = malloc(64);
    release();
    g_obj->buf[0] = 'U'; /* UAF write */
}
int main(void) { trigger(); return 0; }
