/* CWE-190: Loop accumulator overflow → undersized allocation
 * total += size in loop without overflow check.
 * Two requests of 0x80000001 → total wraps to small value.
 * EXPECT: TP
 */
#include <stdlib.h>
#include <string.h>
void merge_buffers(int *sizes, int n, char **chunks) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        total += sizes[i]; /* no overflow check */
    }
    char *buf = (char*)malloc(total);
    if (!buf) return;
    int offset = 0;
    for (int i = 0; i < n; i++) {
        memcpy(buf + offset, chunks[i], sizes[i]);
        offset += sizes[i];
    }
    free(buf);
}
