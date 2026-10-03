/* malloc(n) + memcpy(buf, src, n*2) 写入系数大于分配 → 溢出 */
#include <stdlib.h>
#include <string.h>
int main(int c, char** v) {
    size_t n = c > 1 ? strlen(v[1]) : 4;
    char* buf = malloc(n);
    memcpy(buf, "abcdefgh", n * 2);
    free(buf);
    return 0;
}
