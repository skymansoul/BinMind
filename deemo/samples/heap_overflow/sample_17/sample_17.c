/*
 * sample_17 — sprintf 导致的堆溢出.
 *
 * 漏洞: sprintf 写入到堆缓冲区, 但格式化后的字符串
 * 长度超过了分配大小 → 堆溢出.
 *
 * 这是真实世界中非常常见的漏洞模式.
 * CWE-120: Buffer Copy without Checking Size of Input.
 */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *buf = (char *)malloc(16);
    if (!buf) return 1;

    /* sprintf 产生超过 16 字节的输出 → 溢出 */
    sprintf(buf, "This string is way too long for a 16-byte buffer!");

    printf("buf = %s\n", buf);
    free(buf);
    return 0;
}
