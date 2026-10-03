/* CVE-2022-3602 — OpenSSL punycode 堆 off-by-one。
 * malloc(88) + memcpy(89)。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(88);
    if (!buf) return 1;
    char src[96];
    memset(src, 'D', sizeof(src));
    memcpy(buf, src, 89);                 /* off-by-one 越界 */
    free(buf);
    return 0;
}
