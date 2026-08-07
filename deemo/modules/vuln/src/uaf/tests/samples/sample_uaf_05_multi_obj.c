/* sample_uaf_05_multi_obj.c — 多对象: 两个malloc, 一个free, 另一个仍use */
#include <stdlib.h>
void test() {
    int *a = (int*)malloc(64);
    int *b = (int*)malloc(64);  /* 独立对象 */
    *a = 1; *b = 2;
    free(a);    /* 释放a */
    a = NULL;
    *b = 99;    /* safe — b未被释放 (不同对象) */
}
int main() {
    test();
    return 0;
}
