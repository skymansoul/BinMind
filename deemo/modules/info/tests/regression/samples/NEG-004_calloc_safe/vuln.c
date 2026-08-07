/* NEG-004 — calloc 分配量等于 memcpy 写入量 → 安全, 不应报警 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void calloc_safe(int n_records, size_t record_sz) {
    size_t total = n_records * record_sz;
    char *buf = calloc(n_records, record_sz);
    if (!buf) return;
    memcpy(buf, "dummy data", 10);   /* 写入远小于分配 → 安全 */
    printf("calloc safe: total=%zu\n", total);
    free(buf);
}

int main(int c, char **v) {
    calloc_safe(64, 32);  /* 分配 2048 字节 */
    return 0;
}
