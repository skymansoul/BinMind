
/* 良性: 自一致分配拷贝 — malloc(n); memcpy(dst, src, n).
   写入容量与分配容量溯源等价, ACPE 应滤除。 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void copy_sized(size_t n, const char *src) {
    char *dst = (char *)malloc(n);
    memcpy(dst, src, n);
    free(dst);
}

int main(void) {
    char data[128];
    memset(data, 'X', sizeof(data));
    copy_sized(sizeof(data), data);
    return 0;
}
