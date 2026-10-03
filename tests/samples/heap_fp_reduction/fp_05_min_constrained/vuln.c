/*
 * FP-05: min 约束
 *
 * 使用 min(size, MAX_SIZE) 模式限制分配大小。
 * 检测器若只追踪 malloc 参数而不理解 min 语义, 会误报。
 *
 * 预期: 基准检测器 → 误报
 *       增强管线 → 约束检测识别 min(size, 128) → 正确过滤
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MIN(a,b) ((a)<(b)?(a):(b))

int main(void) {
    int input_size = 1024 * 1024;  // 模拟大输入
    int safe_size = MIN(input_size, 128);
    char *buf = malloc(safe_size);
    if (!buf) return 1;
    memcpy(buf, "safe within 128 bytes", 22);
    printf("buf: %s\n", buf);
    free(buf);
    return 0;
}
