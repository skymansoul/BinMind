/* tainted写入变量alloc: malloc(n)+memcpy(n) — 同源taint, 写入受alloc约束 */
#include <stdlib.h>
#include <string.h>
void taint_var_safe(int argc, char **argv) {
    int n = atoi(argv[1]);
    char *buf = malloc(n);
    if (!buf) return;
    memcpy(buf, src, n);
    free(buf);
}
