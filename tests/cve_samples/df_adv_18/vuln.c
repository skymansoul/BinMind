/* df_adv_18 — SAFE: macro-wrapped free with NULL assignment then free(NULL)
 * SAFE_FREE sets ptr=NULL, so free(ptr) is free(NULL) — no-op, safe
 * DFSV weakness: should NOT flag this (FP test for macro handling)
 */
#include <stdlib.h>
#define SAFE_FREE(x) do { free(x); x = NULL; } while(0)
int main() {
    char *ptr = malloc(256);
    SAFE_FREE(ptr);
    free(ptr);  /* safe: ptr is NULL after SAFE_FREE, free(NULL) is no-op */
    return 0;
}
