// HEAP-FP-008: alloc和copy完全相等——安全代码，应被过滤
// malloc(N)后memcpy(N) → 看起来可疑但实际合法
// 测试目的: 验证FP过滤器对这种常见安全模式不报警
// 期望: 不报告(安全代码——拷贝大小等于分配大小)

#include <string.h>
#include <stdlib.h>

void safe_copy(const char *in, int len) {
    char *buf = malloc(len);       // 精确分配
    if (!buf) return;
    memcpy(buf, in, len);          // 精确拷贝 → 安全
    free(buf);
}

int main() {
    char data[128];
    memset(data, 'S', 128);
    safe_copy(data, 128);
    return 0;
}
