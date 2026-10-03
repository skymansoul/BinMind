/* NEG-006 — realloc 增大后写入不溢出 → 安全 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void realloc_grow_safe(const char *src, int initial, int final) {
    char *buf = malloc(initial);
    if (!buf) return;
    /* realloc 增大到 final, 写入仍用 final → 安全 */
    buf = realloc(buf, final);
    memcpy(buf, src, final);
    printf("realloc safe: %d -> %d\n", initial, final);
    free(buf);
}

int main(int c, char **v) {
    char data[2048];
    memset(data, 'F', sizeof(data));
    realloc_grow_safe(data, 256, 2048);  /* 增大后安全 */
    return 0;
}
