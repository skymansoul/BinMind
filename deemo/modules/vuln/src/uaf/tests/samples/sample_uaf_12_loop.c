/* sample_uaf_12_loop.c — 循环中的UAF: free在循环内, use在循环后 */
#include <stdlib.h>
void test() {
    int *p = (int*)malloc(64);
    for (int i = 0; i < 5; i++) {
        p[i] = i;
    }
    free(p);
    for (int i = 0; i < 3; i++) {
        p[i] = 0;  /* UAF — p已释放 */
    }
}
int main() {
    test();
    return 0;
}
