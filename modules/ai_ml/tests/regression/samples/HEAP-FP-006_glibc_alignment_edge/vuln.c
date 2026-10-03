// HEAP-FP-006: glibc对齐边界测试——malloc(48)实际可用56字节
// glibc x86_64: malloc(48)的usable=56, malloc(56)的usable=56
// 测试目的: 验证堆分配器模型能区分"看起来溢出但实际在可用空间内"
//   alloc=48 → usable=56, copy=52 → 未溢出
//   alloc=48 → usable=56, copy=60 → 溢出
// 期望: 前者不报告(安全), 后者报告(溢出)

#include <string.h>
#include <stdlib.h>

void test_align_edge(const char *in, int with_overflow) {
    char *buf = malloc(48);        // 请求48, glibc给usable=56
    if (!buf) return;
    if (with_overflow) {
        memcpy(buf, in, 60);       // VULN: 60 > usable(56)
    } else {
        memcpy(buf, in, 52);       // SAFE: 52 ≤ usable(56)
    }
    free(buf);
}

int main() {
    char data[128];
    memset(data, 'A', 128);
    test_align_edge(data, 1);  // trigger overflow path
    return 0;
}
