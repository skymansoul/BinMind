/* heap_safe_03: malloc(128), write 64 → safe
 * SAFE: allocation size > write size → safe
 * Expected: CORRECT SAFE
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int safe_smaller_write(const char *input) {
    char *buf = (char *)malloc(128);
    if (!buf) return -1;
    memcpy(buf, input, 64);  // 64 < 128 → SAFE
    buf[63] = 0;
    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main(void) {
    char dummy[64];
    memset(dummy, 'D', 64);
    dummy[63] = 0;
    return safe_smaller_write(dummy);
}
