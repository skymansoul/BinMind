/* heap_overflow_07: sprintf into undersized heap buffer
 * CWE-122: buf=malloc(16); sprintf(buf, "%s%d...", long_str, val)
 * Expected: TRUE POSITIVE (format string produces > 16 bytes)
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int trigger_sprintf_overflow(void) {
    char *buf = (char *)malloc(16);
    if (!buf) return -1;
    sprintf(buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // 28 chars + null → overflow
    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main(void) {
    return trigger_sprintf_overflow();
}
