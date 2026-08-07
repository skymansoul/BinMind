/* CVE-2025-same-offset-accumulate CWE-122: 同偏移重复写入累积溢出.
 * 每次 memcpy(buf, src, 64) 写到相同偏移 0, 5 次循环后累积 320 > 256.
 * 真实案例: 数据包处理循环, 固定缓冲区接收变长输入, 每次覆盖相同起始位置.
 * 现有工具只检查单次写入, 忽略同偏移重复写入的累积效果.
 */
#include <stdlib.h>
#include <string.h>

#define BUF_SZ   256
#define WRITE_SZ 64
#define ITERS    5

void recv_loop(const unsigned char *input, size_t len) {
    unsigned char *buf = malloc(BUF_SZ);
    if (!buf) return;
    size_t consumed = 0;
    /* 每次覆盖 buf[0..63], 单独安全但累积超过分配 */
    for (int i = 0; i < ITERS && consumed + WRITE_SZ <= len; i++) {
        memcpy(buf, input + consumed, WRITE_SZ);
        consumed += WRITE_SZ;
    }
    free(buf);
}

int main() {
    unsigned char d[512];
    memset(d, 'B', sizeof(d));
    recv_loop(d, sizeof(d));
    return 0;
}
