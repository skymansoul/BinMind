/* df_adv_25 — double-free in error-handling chain (3 levels)
 * func3 calls free, func2 error path calls free, func1 calls free
 */
#include <stdlib.h>
char *g = NULL;
void func3() { if (g) { free(g); } }
void func2(int err) {
    if (err) { func3(); }
    /* note: g not nulled after func3 */
}
void func1(int err) {
    g = malloc(128);
    func2(err);
    free(g);  /* if err: func3 already freed g => double-free */
}
int main() { func1(1); return 0; }
