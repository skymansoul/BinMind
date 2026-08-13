#include <stdlib.h>
__attribute__((noinline)) int proc(int err) {
    char *p = malloc(16);
    if (!p) return -1;
    if (err) { free(p); return -2; }
    p[0] = 1;          /* 正常路径: p未释放 */
    free(p);
    return 0;
}
int main(void){ proc(0); return 0; }
