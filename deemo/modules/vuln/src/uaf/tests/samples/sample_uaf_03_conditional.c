/* sample_uaf_03_conditional.c — 条件路径UAF: free在分支中 */
#include <stdlib.h>
void process(int should_free) {
    int *p = (int*)malloc(64);
    *p = 42;
    if (should_free) {
        free(p);   /* free只在should_free=1时执行 */
    }
    *p = 99;  /* 若should_free=1 → UAF; 若=0 → safe */
}
int main() {
    process(1);  /* triggers UAF path */
    return 0;
}
