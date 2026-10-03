// HEAP-FP-007: 间接值流——size通过算术运算传递
// 原始size经过 mul→add→sub 链后才到达malloc和memcpy
// 测试目的: 验证值流引擎能追踪算术运算链
// 期望: 检出堆溢出(size_base=40*4=160, alloc=80, copy=160)

#include <string.h>
#include <stdlib.h>

void indirect_size_vuln(int count, int unit_size) {
    int total = count * unit_size;       // total = 10 * 16 = 160 (未用)
    int half = total / 2;                // half = 80
    char *buf = malloc(half);            // alloc = 80
    if (!buf) return;
    memcpy(buf, "data", total);          // VULN: total(160) > alloc(80)
    free(buf);
}

int main() {
    indirect_size_vuln(10, 16);
    return 0;
}
