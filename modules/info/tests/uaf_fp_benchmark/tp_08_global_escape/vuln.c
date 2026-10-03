/* UAF TP sample */
#include <stdlib.h>
typedef struct { int v; } obj_t;
static obj_t *g_ptr;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    g_ptr = p;
    free(p);
    g_ptr->v = 7;
    return 0;
}
