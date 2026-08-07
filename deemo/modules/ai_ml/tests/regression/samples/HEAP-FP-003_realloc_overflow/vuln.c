// HEAP-FP-003: realloc扩展后溢出
// realloc(ptr, new_size) → 若new_size不够, memcpy仍溢出
// 测试目的: 验证realloc的分配大小追踪是否正常
// 期望: 检出堆溢出

#include <string.h>
#include <stdlib.h>

void realloc_vuln(const char *in, int len) {
    char *buf = malloc(32);
    if (!buf) return;
    buf = realloc(buf, 48);     // 扩展到48字节
    if (!buf) return;
    memcpy(buf, in, len);       // VULN: len=128 > realloc(48)
    free(buf);
}

int main() {
    char data[512];
    memset(data, 'R', 512);
    realloc_vuln(data, 128);
    return 0;
}
