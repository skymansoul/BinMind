/* df_adv_23 — double-free via pointer arithmetic reset
 * p = malloc(128); q = p + 8; free(q-8); free(p)
 */
#include <stdlib.h>
int main() {
    char *p = (char*)malloc(128);
    char *q = p + 8;
    free(q - 8);  /* frees p's allocation */
    free(p);      /* double-free: q-8 == p */
    return 0;
}
