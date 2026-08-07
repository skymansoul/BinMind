/*
 * strcat 链式堆溢出 — 对同一缓冲区反复调用 strcat,
 * 每次追加固定长度, 累积超出分配.
 * alloc: 64, 每次追加 20 字节, 4 次 → 80 > 64
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void strcat_chain(const char **inputs, int count) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    buf[0] = '\0';

    for (int i = 0; i < count; i++) {
        /* 漏洞: 不检查累积长度是否超出 64 */
        strcat(buf, inputs[i]);
    }
    printf("result(len=%zu): %s\n", strlen(buf), buf);
    free(buf);
}

int main(void) {
    const char *inputs[] = {
        "AAAAAAAAAAAAAAAAAAAA",  /* 20 */
        "BBBBBBBBBBBBBBBBBBBB",  /* 20 */
        "CCCCCCCCCCCCCCCCCCCC",  /* 20 */
        "DDDDDDDDDDDDDDDDDDDD",  /* 20 → total 80 > 64 */
    };
    strcat_chain(inputs, 4);
    return 0;
}
