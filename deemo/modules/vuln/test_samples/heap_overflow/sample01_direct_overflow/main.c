/* Direct heap overflow — 简单越界写入.
 *
 * CVE pattern: malloc(64), write at offset 96.
 * 这是最基础的堆溢出形式, 任何检测器都应检出.
 * Expected: TP (confidence ≥ 0.90)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    memset(buf, 'A', 96);  /* OVERFLOW: 写入96字节, alloc仅64 */
    buf[0] = '\0';
    free(buf);
    return 0;
}
