/* df_adv_22 — struct field alias through function param
 * caller sets s->a = s->b; callee frees s->a; caller frees s->b
 */
#include <stdlib.h>
typedef struct { char *a; char *b; } Pair;
void helper(Pair *s) { free(s->a); }
int main() {
    Pair *s = malloc(sizeof(Pair));
    s->a = malloc(32);
    s->b = s->a;  /* alias */
    helper(s);
    free(s->b);   /* double-free: s->b aliases s->a freed in helper */
    free(s);
    return 0;
}
