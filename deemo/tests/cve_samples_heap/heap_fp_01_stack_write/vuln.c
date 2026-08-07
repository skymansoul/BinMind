/* 误报测试: malloc存在但memcpy目标是栈缓冲区
 * 预期: 指针身份追踪应识别write目标≠alloc目标 → FILTERED
 * 旧行为: 检测器将所有malloc和memcpy配对 → FP
 */
#include <stdlib.h>
#include <string.h>

void test() {
    char *heap_buf = (char*)malloc(256);
    char stack_buf[64];
    /* 此memcpy写入stack_buf (栈), 与heap_buf无关 */
    memcpy(stack_buf, "test_data", 9);
    /* 旧检测器: 看到malloc(256)和memcpy, 比较 9 vs 256 → SAFE
     * 但若遇到 memcpy(stack_buf, ..., 512) 则会误报为堆溢出 */
    free(heap_buf);
}

int main() {
    test();
    return 0;
}
