/* df_adv_27 — SAFE: union reinterpretation, different member same address
 * Free one union member is same as free the union base. Not a double-free
 * if only freed once. But two different union accesses look like 2 frees.
 */
#include <stdlib.h>
typedef union { char *str; int *ints; } Data;
int main() {
    Data *d = malloc(sizeof(Data));
    d->str = malloc(32);
    free(d->str);
    d->str = NULL;  /* reset */
    free(d);         /* safe: only freeing d, not d->str again */
    return 0;
}
