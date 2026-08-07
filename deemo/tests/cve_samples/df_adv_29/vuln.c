/* df_adv_29 — SAFE: conditional reallocation with flag
 * flag controls whether realloc happens; only free once per path
 */
#include <stdlib.h>
int main(int argc, char **argv) {
    char *p = malloc(64);
    int freed = 0;
    if (argc > 2) {
        free(p);
        freed = 1;
    }
    if (!freed) {
        free(p);
    }
    /* exactly one free per path: safe */
    return 0;
}
