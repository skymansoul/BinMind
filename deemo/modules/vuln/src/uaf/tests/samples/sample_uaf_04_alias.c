/* sample_uaf_04_alias.c — 别名追踪: 两个寄存器指向同一对象, free一个, use另一个 */
#include <stdlib.h>
void test() {
    int *p = (int*)malloc(64);
    int *q = p;     /* q是p的别名 — 指向同一对象 */
    *p = 42;
    free(p);        /* 释放p */
    p = NULL;
    *q = 99;        /* UAF via q — q仍指向已释放内存 */
}
int main() {
    test();
    return 0;
}
