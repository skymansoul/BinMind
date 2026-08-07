/* CWE-191: Integer underflow in (size - header) calculation
 * size=0 → (size-8) wraps to huge unsigned → malloc(2^64-8).
 * On 32-bit platform or with small size, header subtraction underflows.
 * EXPECT: TP
 */
#include <stdlib.h>
#include <string.h>
void parse_packet(unsigned int size, char *data) {
    if (size < 8) return;           /* signed comparison */
    unsigned int payload = size - 8; /* underflow if size < 8 (bypass guard?) */
    char *buf = (char*)malloc(payload);
    if (!buf) return;
    memcpy(buf, data + 8, payload);
    free(buf);
}
