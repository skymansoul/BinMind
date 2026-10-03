/* 包装函数间接安全: malloc(256)→copy_wrapper(buf,64) — 间接调用路径 */
#include <stdlib.h>
#include <string.h>
void copy_wrapper(char *dst, int len) {
    memcpy(dst, src, len);
}
void wrapper_safe() {
    char *buf = malloc(256);
    if (!buf) return;
    copy_wrapper(buf, 64);
    free(buf);
}
