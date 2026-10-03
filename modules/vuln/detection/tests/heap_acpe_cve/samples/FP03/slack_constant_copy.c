
/* 良性: 分配器 slack 区内常数拷贝.
   malloc(100) 实际可用 112 字节, 拷贝 112 在可用容量内。 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void slack_copy(void) {
    char *dst = (char *)malloc(100);
    memcpy(dst, "0123456789012345678901234567890123456789"
                "0123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567",
           112);                     /* ≤ usable 112 */
    free(dst);
}

int main(void) {
    slack_copy();
    return 0;
}
