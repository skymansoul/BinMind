/* CWE-680: Integer overflow to buffer overflow via snprintf return value.
   snprintf returns what WOULD have been written → used as size for next alloc */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char tmp[16]; int needed = snprintf(tmp, 16, "%s", argv[1]);
    char *buf = malloc(needed); /* needed > 16 but alloc'd as if ≤16 */
    if (!buf) return 1;
    memcpy(buf, argv[1], needed); /* overflow if argv[1] > alloc */
    free(buf); return 0;
}
