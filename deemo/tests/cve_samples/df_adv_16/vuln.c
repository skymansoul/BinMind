/* df_adv_16 — multi-hop alias chain double-free
 * p -> q -> r -> s, free(s) then free(p) all alias same allocation
 * DFSV weakness: 3-hop alias chain not resolved
 */
#include <stdlib.h>
int main() {
    char *p = malloc(128);
    char *q = p;
    char *r = q;
    char *s = r;
    free(s);
    free(p);  /* double-free via 3-hop alias chain */
    return 0;
}
