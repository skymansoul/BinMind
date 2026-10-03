/* heap_overflow_01 — malloc(64) 后写入 128 字节
 * 对应 CWE-122: Heap-based Buffer Overflow
 * 编译: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vuln_func(const char *input) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    strcpy(buf, input);  /* 溢出点: input 长度不受限 */
    printf("copied: %s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <input>\n", argv[0]); return 1; }
    vuln_func(argv[1]);
    return 0;
}
