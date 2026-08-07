/* sample_uaf_10_safe_no_free.c — safe: malloc但未free, 正常使用 */
#include <stdlib.h>
void test() {
    int *p = (int*)malloc(64);
    *p = 42;
    p[1] = 99;
    /* 无free — 无UAF (虽然内存泄漏) */
}
int main() {
    test();
    return 0;
}
