/* CVE-2021-3156: Sudo Baron Samedit heap overflow — duplicate entry */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = malloc(64);
    if (!buf) return 1;
    memset(buf + 48, 0, 128);  /* overflow: buffer[48..175] exceeds alloc */
    free(buf);
    return 0;
}
