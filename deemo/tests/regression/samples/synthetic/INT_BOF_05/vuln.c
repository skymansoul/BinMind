/* CWE-190: Truncation from 64-bit to 32-bit in size calculation */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void process(size_t count) {
    int truncated = (int)count; /* 64-bit → 32-bit truncation */
    char *buf = malloc(truncated + 1);
    if (!buf) return;
    memset(buf, 'A', count); /* actual write uses untruncated count */
    free(buf);
}
int main(void) { process(0x100000001ULL); return 0; }
