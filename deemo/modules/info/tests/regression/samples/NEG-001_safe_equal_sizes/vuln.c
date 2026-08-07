/* NEG-001 — alloc和write使用相同常量大小 → 安全, 不应报警 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BUF_SIZE 256

void safe_copy(const char *src) {
    char *buf = malloc(BUF_SIZE);
    if (!buf) return;
    memcpy(buf, src, BUF_SIZE);  /* alloc=256, write=256 → 安全 */
    printf("safe copy done\n");
    free(buf);
}

int main(int c, char **v) {
    char data[BUF_SIZE];
    memset(data, 'A', BUF_SIZE);
    safe_copy(data);
    return 0;
}
