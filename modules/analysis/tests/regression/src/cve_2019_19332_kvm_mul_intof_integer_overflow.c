#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// cve_2019_19332 Integer Overflow: signed mul: (int)n*(int)size overflows

void kvm_mul_intof_mul_overflow(int count) {
    // count*sizeof(int) 可能溢出 → malloc 分配过小缓冲区
    size_t sz = (size_t)count * sizeof(int);
    if (sz < 4096) {  // 安全门卫被溢出绕过: count=1073741824→sz=0
        char *buf = (char *)malloc(sz);
        if (!buf) { printf("kvm_mul_intof: malloc NULL\n"); return; }
        // 实际写入远超分配大小 (若sz被截断)
        memset(buf, 0, sz > 0 ? sz : 4096);
        free(buf);
    }
    printf("kvm_mul_intof: done\n");
}

void kvm_mul_intof_safe_mul(int count) {
    size_t sz = (size_t)count * sizeof(int);
    // 溢出检测: 逆运算不相等即溢出
    if (sz / sizeof(int) != (size_t)count) {
        printf("kvm_mul_intof: overflow rejected\n");
        return;
    }
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memset(buf, 0, sz);
    free(buf);
    printf("kvm_mul_intof: ok\n");
}

int main() {
    printf("cve_2019_19332 intof test\n");
    kvm_mul_intof_mul_overflow(1073741824);
    kvm_mul_intof_safe_mul(1073741824);
    return 0;
}
