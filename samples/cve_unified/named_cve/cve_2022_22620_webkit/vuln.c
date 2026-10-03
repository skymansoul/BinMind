/* CVE-2022-22620 — WebKit/iOS Safari heap use-after-free → overflow pattern
 * 简化模式: 多次 realloc 后仍使用旧指针.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int process_buffer(size_t n) {
    char *buf = (char *)malloc(n);
    if (!buf) return -1;
    memset(buf, 'A', n);
    /* realloc to grow; old pointer invalidated */
    char *new_buf = (char *)realloc(buf, n * 2);
    if (!new_buf) { free(buf); return -1; }
    /* bug: still writes to old 'buf' pointer (now freed/invalid) */
    memset(buf, 'B', n); /* UAF + potential heap corruption */
    free(new_buf);
    return 0;
}

int main(void) {
    process_buffer(128);
    return 0;
}
