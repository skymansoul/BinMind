/* SAFE: size_t arithmetic — no truncation, no overflow at realistic values
 * size_t n, size_t size → n*size done in size_t → no 32-bit wrap.
 * EXPECT: TN
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
void safe_multiply(size_t n, size_t size, char *src) {
    if (n > SIZE_MAX / size) return; /* safe overflow check */
    size_t total = n * size;
    char *buf = (char*)malloc(total);
    if (!buf) return;
    memcpy(buf, src, total);
    free(buf);
}
