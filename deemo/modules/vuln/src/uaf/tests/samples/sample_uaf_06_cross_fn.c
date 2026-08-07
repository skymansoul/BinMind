/* sample_uaf_06_cross_fn.c — 跨函数UAF: 函数返回堆指针, caller free后use */
#include <stdlib.h>
int* create_buffer(int sz) {
    return (int*)malloc(sz);
}
void test() {
    int *buf = create_buffer(64);
    *buf = 42;
    free(buf);     /* caller释放被调函数分配的指针 */
    *buf = 99;     /* UAF */
}
int main() {
    test();
    return 0;
}
