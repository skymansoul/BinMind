/* df_adv_24 — SAFE: different allocations, same variable name
 * p is reassigned to new allocation between two frees
 */
#include <stdlib.h>
int main() {
    char *p;
    p = malloc(64);
    free(p);
    p = malloc(64);  /* new allocation: different address */
    free(p);          /* safe: freeing different allocation */
    return 0;
}
