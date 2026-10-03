/* malloc(n) + memcpy(buf, src, n) 共享系数相等 → 安全 */
#include <stdlib.h>
#include <string.h>
int main(int c, char** v) {
    size_t n = c > 1 ? strlen(v[1]) : 4;
    char* buf = malloc(n + 1);
    memcpy(buf, "abc", n);
    buf[n] = 0;
    free(buf);
    return 0;
}
