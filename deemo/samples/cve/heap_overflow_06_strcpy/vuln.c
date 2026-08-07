/* heap_overflow_06: strcpy into undersized heap buffer
 * CWE-122: buf=malloc(8); strcpy(buf, long_string)
 * Pattern: strcpy has no length check, overflows if src > dst
 * Expected: TRUE POSITIVE
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int trigger_strcpy_overflow(void) {
    const char *long_str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 33 bytes + null
    char *buf = (char *)malloc(8);
    if (!buf) return -1;
    strcpy(buf, long_str);  // OVERFLOW: 34 bytes into 8-byte buffer
    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main(void) {
    return trigger_strcpy_overflow();
}
