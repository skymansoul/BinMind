/* CWE-129: Array index from addition overflow
 * base + offset may overflow, indexing outside allocated heap buffer.
 * EXPECT: TP
 */
#include <stdlib.h>
#include <string.h>
void write_at_offset(int base, int offset, char value) {
    char *buf = (char*)malloc(256);
    if (!buf) return;
    int idx = base + offset;  /* may overflow if base+offset > INT_MAX */
    if (idx < 256) {           /* signed check: negative idx passes */
        buf[idx] = value;      /* negative idx → heap underflow */
    }
    free(buf);
}
