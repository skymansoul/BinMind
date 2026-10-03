/* integer_overflow_01 — 整数溢出导致 malloc(0) 或 buffer underwrap
 * 对应 CWE-190: Integer Overflow or Wraparound
 * 编译: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copy_with_size(unsigned short count, const char *src) {
    unsigned int size = count * 256;  /* 若 count=257, size=257*256=65792 但在 unsigned short 下溢出为 256 */
    char *buf = (char *)malloc(size);
    if (!buf) return;
    memcpy(buf, src, count * 256);  /* 实际拷贝远超分配大小 */
    free(buf);
}

int main(int argc, char **argv) {
    unsigned short n = 10;
    if (argc >= 2) n = (unsigned short)atoi(argv[1]);
    copy_with_size(n, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    return 0;
}
