/* heap_overflow_basic_01 — 经典堆溢出: malloc(16) + memcpy(32B)
 * 误报诱因: 简单代码无守卫, 几乎所有工具都检出.
 * 我们的优势: allocator model 正确识别 malloc(16) → effective=24B,
 *   若写入 > 24B 才判定溢出, 比直接比较 32>16 更精确.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(16);
    if (!buf) return 1;
    memcpy(buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32); /* overflow: 32 > 24(effective) */
    printf("%s\n", buf);
    free(buf);
    return 0;
}
