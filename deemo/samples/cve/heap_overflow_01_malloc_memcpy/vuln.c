/* heap_overflow_01: Classic malloc(N) + memcpy(M) where M > N
 * CWE-122: Heap-based Buffer Overflow
 * Pattern: allocated 64 bytes, write 128 bytes → overflow by 64
 * Expected: TRUE POSITIVE (any static analyzer should find this)
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int trigger_overflow(const char *input) {
    size_t alloc_sz = 64;
    size_t write_sz = 128;
    char *buf = (char *)malloc(alloc_sz);
    if (!buf) return -1;
    memcpy(buf, input, write_sz);  // OVERFLOW: 128 > 64
    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    char dummy[256];
    memset(dummy, 'A', sizeof(dummy));
    dummy[255] = 0;
    return trigger_overflow(dummy);
}
