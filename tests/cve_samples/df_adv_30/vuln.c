/* df_adv_30 — double-free through nested wrapper chain
 * wrap_free calls inner_free calls actual_free calls free
 * Plus a direct free after wrap_free
 */
#include <stdlib.h>
char *target = NULL;
void actual_free() { free(target); }
void inner_free() { actual_free(); }
void wrap_free() { inner_free(); }
int main() {
    target = malloc(128);
    wrap_free();
    free(target);  /* double-free: target freed via wrap->inner->actual */
    return 0;
}
