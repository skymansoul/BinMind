/* CVE-2013-2094: Linux perf_event 堆溢出 —— 简化: 整数溢出导致小分配大写入 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void perf_read_event(int count, char *data) {
    size_t alloc_size = count * sizeof(long);
    /* BUG: count*sizeof(long) 可能回绕 → alloc_size 远小于实际需求 */
    char *buf = malloc(alloc_size);
    memcpy(buf, data, count * 8);
    free(buf);
}
int main() { perf_read_event(0x20000001, "AAAA"); return 0; }
