/*
 * CVE-26: realloc增长后安全 — realloc扩大缓冲区, 后续写入在新边界内
 *
 * 模式: malloc(32), realloc(buf, 256), memcpy(buf+200, src, 56)
 * 安全: realloc后usable(256)=264, write_end=200+56=256 < 264 → SAFE
 * 常见误报: 只看初始malloc(32), 不跟踪realloc增长 → 误报溢出
 *
 * 对应: 类似 CVE-2020-28052 (bcrypt realloc 堆溢出)
 * 检测预期: PROVEN_SAFE (realloc大小更新后)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;

    buf = (char *)realloc(buf, 256);
    if (!buf) return 1;

    char data[256];
    memset(data, 'R', sizeof(data));
    memcpy(buf + 200, data, 56);

    printf("realloc_grow_safe done\n");
    free(buf);
    return 0;
}
