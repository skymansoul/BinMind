#include <stdio.h>
#include <stdlib.h>
/* CVE-2019-11477 模式: 整数溢出导致过小分配 */
void process_packets(int count, int pkt_size) {
    /* BUG: count*pkt_size可能溢出, 导致malloc分配过小 */
    int alloc_size = count * pkt_size;
    char *buf = malloc(alloc_size);
    if (!buf) return;
    for (int i = 0; i < count; i++) {
        buf[i * pkt_size] = 0;  /* 可能越界写 */
    }
    free(buf);
}
int main() {
    process_packets(65536, 65536); /* 乘积溢出 */
    return 0;
}
