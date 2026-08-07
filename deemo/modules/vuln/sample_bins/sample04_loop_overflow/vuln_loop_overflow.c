/* sample04: 循环索引溢出 — for循环用错误的上界
 *
 * 漏洞类型: Heap overflow via loop bound error
 * 触发条件: 循环使用外部输入作为上界但未与分配大小比较
 * 测试价值: 测试循环感知区间分析的有效性
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void fill_buffer(char *buf, size_t alloc_sz, size_t fill_count) {
    // [VULN] fill_count 可能 > alloc_sz, 循环会溢出
    for (size_t i = 0; i < fill_count; i++) {
        buf[i] = (char)(i & 0xFF);
    }
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <alloc_sz> <fill_count>\n", argv[0]); return 1; }
    size_t alloc = (size_t)atoi(argv[1]);
    size_t fill = (size_t)atoi(argv[2]);
    char *buf = (char *)malloc(alloc);
    if (!buf) return 1;
    fill_buffer(buf, alloc, fill);
    printf("done, buf[0]=%d\n", buf[0]);
    free(buf);
    return 0;
}
