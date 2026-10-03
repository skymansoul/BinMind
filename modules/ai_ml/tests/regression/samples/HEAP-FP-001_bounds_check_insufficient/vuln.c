// HEAP-FP-001: 有边界检查但不充分——常见误报源
// memcpy前有if(len > alloc_size)检查但检查值与实际值不匹配
// 测试目的: 验证FP过滤器能区分"有检查但不足"vs"有检查且足够"
// 期望: 检出(检查出现在alloc=64但检查阈值是256→不足)

#include <string.h>
#include <stdlib.h>

void process_with_weak_check(const char *in, int len) {
    char *buf = malloc(64);
    if (!buf) return;
    if (len > 256) return;   // 检查不足: 256 > 64实际分配
    memcpy(buf, in, len);    // VULN: len=128通过检查但仍溢出64B分配
    free(buf);
}

int main() {
    char data[512];
    memset(data, 'F', 512);
    process_with_weak_check(data, 128);  // 128 ≤ 256? pass. 128 > 64? overflow!
    return 0;
}
