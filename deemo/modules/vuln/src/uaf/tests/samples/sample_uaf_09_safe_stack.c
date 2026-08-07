/* sample_uaf_09_stack_addr.c — safe: 栈变量地址传给free (不是堆指针, 是编程错误) */
#include <stdlib.h>
void test() {
    int x = 42;
    /* free(&x); — 这是UB, 不会出现在正常程序中 */
    *(&x) = 99;  /* safe — 栈操作 */
    (void)x;
}
int main() {
    test();
    return 0;
}
