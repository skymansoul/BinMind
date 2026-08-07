/* sample_uaf_08_realloc.c — realloc后use旧指针 */
#include <stdlib.h>
void test() {
    int *p = (int*)malloc(32);
    *p = 1;
    int *q = (int*)realloc(p, 128);  /* realloc可能返回新地址, p失效 */
    if (q) {
        *q = 2;
        *p = 99;  /* UAF if realloc moved the block */
    }
}
int main() {
    test();
    return 0;
}
