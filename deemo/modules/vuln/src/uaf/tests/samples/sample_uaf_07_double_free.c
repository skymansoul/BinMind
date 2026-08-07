/* sample_uaf_07_double_free.c — 双重释放: 同一指针被free两次 */
#include <stdlib.h>
void test() {
    int *p = (int*)malloc(64);
    *p = 42;
    free(p);
    free(p);  /* double free — 第二次free时p已悬垂 */
}
int main() {
    test();
    return 0;
}
