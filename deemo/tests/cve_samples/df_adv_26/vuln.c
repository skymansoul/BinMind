/* df_adv_26 — indirect free via function pointer table
 * vtable[0] = closer; closer calls free; then direct free
 */
#include <stdlib.h>
typedef void (*fn_t)(void*);
void closer(void *p) { free(p); }
int main() {
    fn_t fns[2] = {closer, NULL};
    char *buf = malloc(64);
    fns[0](buf);   /* calls closer(buf) => free(buf) */
    free(buf);      /* double-free */
    return 0;
}
