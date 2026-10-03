/*
 * sample_02 — off-by-one 堆溢出.
 *
 * 漏洞: malloc(64)分配64字节, 循环写入65次 → off-by-one溢出.
 * 覆盖相邻堆块的metadata → 潜在的任意写原语.
 *
 * CWE-193: Off-by-one Error.
 */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    for (int i = 0; i <= 64; i++) {  /* off-by-one: 应 < 64 */
        buf[i] = (char)i;
    }

    printf("last byte: %d\n", buf[63]);
    free(buf);
    return 0;
}
