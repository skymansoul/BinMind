/* CVE-2022-0185 Linux kernel: integer overflow in legacy_parse_param.
 * size=0xFFFFFFFF → size+1 wraps to 0 → small kmalloc, copy out of bounds.
 * EXPECT: TP
 */
#include <stdlib.h>
#include <string.h>
void parse_legacy_param(unsigned int size, char *data) {
    if (size > 4096) return;
    unsigned int alloc = size + 1; /* size=0xFFFFFFFF → alloc wraps to 0 */
    char *buf = (char*)malloc(alloc);
    if (!buf) return;
    memcpy(buf, data, size);       /* copy up to 4095 bytes into ~0-byte buf */
    free(buf);
}
