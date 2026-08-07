/* sample01: 基本堆溢出 — malloc后无边界检查的memcpy
 *
 * 漏洞类型: Heap-based buffer overflow
 * 触发条件: user_size > 256 但未检查, memcpy写入超过分配大小
 * 测试价值: 最基础的堆溢出模式, 检测器必须捕获
 * 难度: 低 — 无混淆, 无间接调用
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_input(size_t user_size, const char *input) {
    char *buf = (char *)malloc(user_size);
    if (!buf) return;
    // [VULN] 未检查 user_size 是否等于 strlen(input)
    // 若 input 比 user_size 长 → 堆溢出
    memcpy(buf, input, user_size + 32);  // 故意多写32字节
    printf("processed: %s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <size> <data>\n", argv[0]);
        return 1;
    }
    size_t sz = (size_t)atoi(argv[1]);
    process_input(sz, argv[2]);
    return 0;
}
