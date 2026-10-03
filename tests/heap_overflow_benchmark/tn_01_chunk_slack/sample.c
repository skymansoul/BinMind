/*
 * TN-01: Chunk Slack Makes Offset Safe (NO OVERFLOW)
 *
 * malloc(20) → glibc实际分配32B chunk → 可用24B (含next chunk prev_size)
 * buf[20]写入4字节 (offset=20, write_end=24) → 不溢出
 *
 * 正则检测器会误报: 20+4>20 → 假阳性
 * LPVRA应判定: SAFE → FILTER (write_end=24 ≤ effective_boundary=24)
 */
#include <stdlib.h>
#include <string.h>

int use_chunk_slack(void) {
    char *buf = (char *)malloc(20);
    if (!buf) return -1;

    /* 写入在chunk slack范围内 */
    buf[20] = 'X';  /* offset=20, write=1B, total=21B */
    buf[21] = 'Y';
    buf[22] = 'Z';
    buf[23] = 'W';  /* 安全: 可用空间 = align_up(20+8, 16) - 8 = 24 */

    free(buf);
    return 0;
}

int main(void) {
    return use_chunk_slack();
}
