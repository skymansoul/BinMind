#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-04: 类型截断 — uint64被截断为uint32导致分配不足 */
int main(int argc, char **argv) {
    unsigned long long total = 0x100000001ULL;  /* > 2^32 */
    unsigned int truncated = (unsigned int)total;  /* 截断为1 */
    char *buf = (char *)malloc(truncated);
    if (!buf) return 1;
    memset(buf, 'A', (size_t)total);  /* VULNERABLE: 超出分配 */
    free(buf); return 0;
}
