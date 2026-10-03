/* 经典 off-by-one 堆溢出 (非 CVE, 通用模式)
 *
 * 触发条件: 循环条件使用了 <= 而非 <, 导致多写入一个元素。
 *
 * 测试目标: 循环边界的值域分析 — 检测到循环索引可达到
 * 分配大小 (i == size) 导致的 off-by-one。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void copy_with_offbyone(char *dst, const char *src, size_t n) {
    size_t i;
    /* BUG: i <= n 应改为 i < n */
    for (i = 0; i <= n; i++) {
        dst[i] = src[i];
    }
}

int main(int argc, char **argv) {
    const char *input;
    size_t len;
    char *buf;

    input = (argc >= 2) ? argv[1] : "AAAA";
    len = strlen(input);

    buf = (char *)malloc(len);
    if (!buf) return 1;

    /* len 字节分配, 写入 len+1 字节 (含null) */
    copy_with_offbyone(buf, input, len);

    free(buf);
    return 0;
}
