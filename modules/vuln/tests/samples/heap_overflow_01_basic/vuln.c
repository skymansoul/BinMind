/* heap_overflow_01 — 基本 malloc-write 堆溢出模式
 *
 * 最简堆溢出: malloc(64) 后写入超过64字节.
 * 测试检测器对基础模式的检出能力.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    /* BUG: memset 写入 128 字节, 超过 64 字节分配 */
    memset(buf, 'A', 128);
    printf("last byte: %c\n", buf[127]);
    free(buf);
    return 0;
}
