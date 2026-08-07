/* heap_fp_01: early-return guard — ensemble should SUPPRESS
 * Pattern: if (len > alloc) return; memcpy(buf, src, len);
 * After early return, len <= alloc on the non-return path → safe.
 * CWE-122 analog: guarded write, NOT exploitable.
 */
#include <stdlib.h>
#include <string.h>
void process(size_t len) {
    char *buf = (char*)malloc(256);
    if (!buf) return;
    if (len > 256) return;        /* early-return guard */
    memcpy(buf, get_input(), len); /* safe: len <= 256 */
    free(buf);
}
