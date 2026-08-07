
/* 良性: 拷贝长度取自分配长度派生 — 分配 n*2, 拷贝 n.
   写入容量是分配容量的严格下界。 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void derived_copy(size_t n, const char *src) {
    char *dst = (char *)malloc(n * 2);
    memcpy(dst, src, n);
    free(dst);
}

int main(void) {
    char data[64];
    memset(data, 'D', sizeof(data));
    derived_copy(64, data);
    return 0;
}
