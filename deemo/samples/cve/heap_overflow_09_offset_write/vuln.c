/* heap_overflow_09: Offset-based write overflow
 * CWE-122: buf=malloc(64); for(i=0;i<10;i++) buf[60+i] = x
 * Pattern: base offset 60 + 10 iterations = buf[60..70) exceeds alloc of 64
 * Expected: TRUE POSITIVE (offset+loop analysis)
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int trigger_offset_overflow(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    for (int i = 0; i < 10; i++) {
        buf[60 + i] = 'X';  // buf[60..70) → overflow by 6 bytes
    }
    buf[69] = 0;
    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main(void) {
    return trigger_offset_overflow();
}
