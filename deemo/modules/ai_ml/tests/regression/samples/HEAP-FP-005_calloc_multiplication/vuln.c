// HEAP-FP-005: calloc乘法溢出
// calloc(n, size) = n*size → 若n*size整数溢出, 分配远小于预期
// 测试目的: 验证calloc两参数处理的正确性
// 期望: 检出堆溢出(整数溢出→分配不足)

#include <string.h>
#include <stdlib.h>

void calloc_overflow_vuln(int nmemb, int size) {
    // 若nmemb=65536, size=65536 → nmemb*size溢出为0 →
    // calloc(0,0)返回min chunk但拷贝全尺寸
    char *buf = calloc(nmemb, size);
    if (!buf) return;
    memcpy(buf, "data", nmemb * size);  // VULN: nmemb*size溢出但memcpy仍尝试
    free(buf);
}

int main() {
    calloc_overflow_vuln(100, 4);  // 小值测试: alloc=400, copy=400 - 安全
    return 0;
}
