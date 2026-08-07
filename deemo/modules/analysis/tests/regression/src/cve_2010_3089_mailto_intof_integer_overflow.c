#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// cve_2010_3089 Integer Overflow: mul overflow: n*sizeof(struct)+4 wraps 32-bit

void mailto_intof_mul_overflow(int count) {
    // count*sizeof(int) 可能溢出 → malloc 分配过小缓冲区
    size_t sz = (size_t)count * sizeof(int);
    if (sz < 4096) {  // 安全门卫被溢出绕过: count=1073741824→sz=0
        char *buf = (char *)malloc(sz);
        if (!buf) { printf("mailto_intof: malloc NULL\n"); return; }
        // 实际写入远超分配大小 (若sz被截断)
        memset(buf, 0, sz > 0 ? sz : 4096);
        free(buf);
    }
    printf("mailto_intof: done\n");
}

void mailto_intof_safe_mul(int count) {
    size_t sz = (size_t)count * sizeof(int);
    // 溢出检测: 逆运算不相等即溢出
    if (sz / sizeof(int) != (size_t)count) {
        printf("mailto_intof: overflow rejected\n");
        return;
    }
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memset(buf, 0, sz);
    free(buf);
    printf("mailto_intof: ok\n");
}

int main() {
    printf("cve_2010_3089 intof test\n");
    mailto_intof_mul_overflow(1073741824);
    mailto_intof_safe_mul(1073741824);
    return 0;
}
