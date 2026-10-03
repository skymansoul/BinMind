/*
 * sample_04 — calloc 整数溢出导致分配不足.
 *
 * 漏洞: calloc(nmemb, size) 在内部计算 nmemb*size,
 * 若乘法回绕, 分配大小远小于预期 → 后续写入溢出.
 *
 * CWE-190: Integer Overflow or Wraparound → CWE-122.
 * CVE-2016-10165 (Little CMS): calloc 整数溢出典型.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    /* nmemb=0x40000001, size=4 → 乘积=0x100000004, 32位回绕=4 */
    size_t nmemb = 0x40000001;
    size_t size = 4;

    int *buf = (int *)calloc(nmemb, size);
    if (!buf) {
        printf("calloc returned NULL (safe)\n");
        return 0;
    }

    /* 若sizeof(size_t)==4 或calloc内部用32位乘法 → 实际只分配了4字节 */
    /* 但我们试图写入远超4字节的数据 */
    for (size_t i = 0; i < 100; i++) {
        buf[i] = (int)i;
    }

    printf("buf[0] = %d\n", buf[0]);
    free(buf);
    return 0;
}
