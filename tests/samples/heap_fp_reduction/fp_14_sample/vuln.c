/*
 * FP-14: 大分配小写入 —— malloc(4096) + store at offset 8
 *
 * 明显的安全操作, 任何检测器都不应报告。
 * 用于验证检测器不会产生"无差别报警"。
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = malloc(4096);
    if (!buf) return 1;
    memset(buf, 0, 4096);
    buf[8] = 'X';  // 偏移 8, 远小于 4096
    printf("large alloc, small write: buf[8]=%c\n", buf[8]);
    free(buf);
    return 0;
}
