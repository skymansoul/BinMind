/* CWE-680: Cast overflow — large size_t truncated to int before malloc
 * size_t len from recv → cast to int → n*2 computed as int → overflow → malloc(small).
 * EXPECT: TP
 */
#include <stdlib.h>
#include <string.h>
void network_handler(size_t len, char *data) {
    int n = (int)len;               /* truncation: size_t→int */
    int alloc_sz = n * 2;           /* n=0x40000000 → alloc_sz wraps negative */
    char *buf = (char*)malloc((size_t)alloc_sz); /* negative→huge unsigned */
    if (!buf) return;
    memcpy(buf, data, len);
    free(buf);
}
