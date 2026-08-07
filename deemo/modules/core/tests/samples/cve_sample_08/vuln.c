/* False positive test 2 — 值区间分析应能证明安全
 * alloc_size 和 write_size 通过常量传播可确定为同一值 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BUF_SIZE 256

void transfer_data(const char *src, size_t len) {
    /* alloc_size 和 write_size 都是 len → 值区间分析应判定安全 */
    char *buf = (char *)malloc(len);
    if (!buf) return;
    memcpy(buf, src, len); /* alloc(len) vs write(len) → safe */
    printf("%s\n", buf);
    free(buf);
}

int main(void) {
    transfer_data("hello world", 12);
    return 0;
}
