/* sample13: 结构体字段溢出 — 内嵌缓冲区越界
 *
 * 漏洞类型: Heap overflow via struct embedded buffer
 * 触发条件: 结构体的最后一个字段是可变长数组,
 *          但分配时未考虑动态大小, 写入时溢出到相邻堆块
 * 测试价值: 结构体字段偏移的精确追踪, padding处理
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    int flags;
    char name[32];   // 固定32字节
    // 后面紧跟可变长数据
    char data[];      // flexible array member
} Packet;

void process_packet(int id, int flags, const char *name, const char *extra, size_t extra_len) {
    // [VULN] 分配时只算了 sizeof(Packet) = 40+32=72字节 (含padding)
    // 但后面写入extra时可能超出
    Packet *pkt = (Packet *)malloc(sizeof(Packet) + extra_len);
    if (!pkt) return;
    pkt->id = id;
    pkt->flags = flags;
    strncpy(pkt->name, name, 32);

    // [VULN] 若extra_len计算有误 (如从网络接收的length字段),
    // 实际写入可能超过分配大小
    memcpy(pkt->data, extra, extra_len + 16);  // BUG: +16超出
    printf("packet %d processed\n", pkt->id);
    free(pkt);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <data>\n", argv[0]); return 1; }
    process_packet(1, 0, "test", argv[1], strlen(argv[1]));
    return 0;
}
