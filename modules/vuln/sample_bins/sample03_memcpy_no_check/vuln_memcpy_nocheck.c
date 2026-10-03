/* sample03: 无边界检查的memcpy — 外部输入直接作为size (跨平台版)

 * 漏洞类型: Heap overflow via tainted memcpy size
 * 触发条件: 外部获取的size直接传给malloc和memcpy, 无任何边界检查
 * 测试价值: 检测size约束传播的有效性
 * 修改: 2026-08-06 — 移除Unix socket依赖, 用read+stdin替代
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle_input(void) {
    unsigned int pkt_size;
    /* 从stdin读取size (模拟外部输入) */
    if (fread(&pkt_size, sizeof(pkt_size), 1, stdin) != 1)
        return;

    /* 限制以防止过大的分配, 但不限制memcpy */
    if (pkt_size > 0x100000)
        pkt_size = 0x100000;

    char *buf = (char *)malloc(pkt_size);
    if (!buf) return;

    /* [VULN] 读取的size可能 != 实际写入量
       实际写入可能超过pkt_size → 堆溢出 */
    int received = (int)fread(buf, 1, pkt_size + 64, stdin);
    if (received > 0) {
        printf("received %d bytes\n", received);
    }
    free(buf);
}

int main(void) {
    fprintf(stderr, "sample03: reads pkt_size then pkt_size+64 from stdin\n");
    handle_input();
    return 0;
}
