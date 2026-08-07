/* NEG-002 — 分配量 > 写入量 → 安全, 不应报警 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void safe_operation(const char *input) {
    char *buf = malloc(4096);    /* 分配 4096 */
    if (!buf) return;
    memcpy(buf, input, 256);     /* 只写 256 → 安全 */
    printf("safe: alloc=4096, write=256\n");
    free(buf);
}

int main(int c, char **v) {
    char data[256];
    memset(data, 'B', 256);
    safe_operation(data);
    return 0;
}
