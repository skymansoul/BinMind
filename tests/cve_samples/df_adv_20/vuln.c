/* df_adv_20 — path-sensitive: 3-way branch, only specific path double-frees
 * if x>0: free(p); if x>10: free(p) again => double-free only when x>10
 */
#include <stdlib.h>
void process(int x) {
    char *p = malloc(64);
    if (x > 0) {
        free(p);
        if (x > 10) {
            free(p);  /* double-free: x>10 implies x>0, both frees execute */
        }
    }
    /* if x<=0: p leaks, no double-free */
}
int main(int argc, char **argv) {
    process(argc);
    return 0;
}
