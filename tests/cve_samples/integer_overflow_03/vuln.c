/* integer_overflow_03 — unsigned short 回绕导致分配不足
 * CWE-190: (unsigned short)n * 256 回绕
 * gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process(unsigned short count, const char *src) {
    unsigned int size = count * 256;
    char *buf = malloc(size);
    memcpy(buf, src, count * 512); /* count*512 > size when count>256 */
    free(buf);
}
int main(int argc, char **argv) {
    unsigned short n = argc > 1 ? (unsigned short)atoi(argv[1]) : 10;
    process(n, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    return 0;
}
