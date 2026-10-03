/* CVE-2023-XXXXX-uaf-loop-accumulate CWE-122: 循环累积写入溢出.
 * 每次 memcpy 单独安全 (64 <= 256), 但5轮循环后累积320 > 256.
 * 真实案例: Linux内核 netlink 消息解析, 固定缓冲区循环接收片段.
 * 现有静态工具 (Angr/Ghidra) 逐指令检查偏移, 无法识别累积效果.
 */
#include <stdlib.h>
#include <string.h>

#define CHUNK_SZ 64
#define N_CHUNKS 5
#define BUF_SZ   256

void process_chunks(const unsigned char *src, size_t src_len) {
    unsigned char *buf = malloc(BUF_SZ);
    if (!buf) return;
    size_t offset = 0;
    /* 每次写入64B安全, 5次后320 > 256溢出 — 静态逐条检查漏报 */
    for (int i = 0; i < N_CHUNKS && offset + CHUNK_SZ <= src_len; i++) {
        memcpy(buf + offset, src + offset, CHUNK_SZ);
        offset += CHUNK_SZ;
    }
    /* use-after-overflow: buf 的实际内容已超出分配边界 */
    buf[BUF_SZ - 1] = '\0';
    free(buf);
}

int main() {
    unsigned char data[512];
    memset(data, 'A', sizeof(data));
    process_chunks(data, sizeof(data));
    return 0;
}
