/* df_adv_21 — SAFE: realloc between frees (legitimate reuse)
 * DFSV weakness: might miss realloc through function pointer or complex expression
 */
#include <stdlib.h>
void work(char **pp) {
    free(*pp);
    *pp = malloc(128);  /* realloc: safe */
    free(*pp);
}
int main() {
    char *p = malloc(64);
    work(&p);
    return 0;
}
