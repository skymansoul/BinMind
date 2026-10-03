/* sample08: 整数溢出 → 堆溢出 — 宽类型到窄类型的截断
 *
 * 漏洞类型: Integer overflow → Heap buffer overflow
 * 触发条件: 64-bit size被截断为32-bit, malloc分配小缓冲区, memcpy用原始大size
 * 测试价值: 类型差异导致的整型溢出, 需要跨类型分析
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void process_batch(uint64_t item_count, const char *data) {
    // [VULN] item_count 是64位, 截断为32位后传递给malloc
    uint32_t truncated = (uint32_t)(item_count * 16);
    char *buf = (char *)malloc(truncated);
    if (!buf) return;
    // memcpy使用原始的64位大小 → 溢出截断后的分配
    memcpy(buf, data, (size_t)(item_count * 16));
    printf("processed %llu items\n", (unsigned long long)item_count);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <count>\n", argv[0]); return 1; }
    uint64_t n = (uint64_t)atoll(argv[1]);
    char data[256] = {0};
    process_batch(n, data);
    return 0;
}
