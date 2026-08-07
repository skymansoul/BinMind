// HEAP-FP-002: 有充分边界检查的安全案例——应被过滤
// malloc(64)且if(len > 64) return → memcpy不会溢出
// 测试目的: 验证FP过滤器能正确识别充分检查并过滤此类告警
// 期望: 不报告(安全代码)

#include <string.h>
#include <stdlib.h>

void process_with_good_check(const char *in, int len) {
    char *buf = malloc(64);
    if (!buf) return;
    if (len > 64) return;    // 充分检查: 64 == 实际分配
    memcpy(buf, in, len);    // 安全: len ≤ 64
    free(buf);
}

int main() {
    char data[512];
    memset(data, 'G', 512);
    process_with_good_check(data, 32);  // 32 ≤ 64 → safe
    return 0;
}
