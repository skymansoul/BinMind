/* heap_strcpy_overflow: strcpy into malloc'd buffer without size check.
   Classic CWE-122 pattern. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = malloc(16);
    if (!buf) return 1;
    strcpy(buf, "This string is way too long for a 16-byte buffer");
    printf("buf=%s\n", buf);
    free(buf);
    return 0;
}
