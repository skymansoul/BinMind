/* CVE-2019-13143 — Espruino jsvStringIteratorPrint heap overflow
 * Pattern: strlen → malloc → sprintf overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char input[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    unsigned len = (unsigned)strlen(input);
    char *buf = (char *)malloc(len);  // no +1 for null terminator
    if (buf) {
        sprintf(buf, "%s!", input);  // HEAP OVERFLOW: writes len + 2 bytes
        printf("CVE-2019-13143: alloc=%u write=%u\n", len, (unsigned)strlen(buf) + 1);
        free(buf);
    }
    return 0;
}
