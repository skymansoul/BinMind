/* 包装函数间接溢出: malloc(32)→copy_wrapper(buf,64) — 间接调用路径 */
#include <stdlib.h>
#include <string.h>
void copy_wrapper(char *dst, int len) {
    memcpy(dst, src, len);
}
void wrapper_overflow() {
    char *buf = malloc(32);
    if (!buf) return;
    copy_wrapper(buf, 64);
    free(buf);
}
