/*
 * TP-03: Off-by-One Heap Overflow (CWE-193)
 *
 * malloc(32) → for i=0..32 (33次迭代) → buf[32]超出边界1字节
 * 经典off-by-one错误, 可被利用覆盖下一chunk的size字段
 *
 * 真实漏洞类比: CVE-2015-0235 (glibc GHOST gethostbyname)
 */
#include <stdlib.h>
#include <string.h>

int copy_string(const char *input) {
    size_t len = strlen(input);        /* len=32 */
    char *buf = (char *)malloc(len);   /* 分配32字节 */

    if (!buf) return -1;

    /* off-by-one: i <= len 而非 i < len */
    for (size_t i = 0; i <= len; i++) {
        buf[i] = input[i];  /* 最后一次写入buf[32] → 溢出1字节 */
    }

    free(buf);
    return 0;
}

int main(void) {
    return copy_string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); /* 32个A */
}
