/* heap_fp_02: constant-size write inside guard — ensemble should SUPPRESS
 * Pattern: if (len < 512) { memcpy(buf, src, 128); }
 * Write size (128) is constant and less than alloc (512) → safe.
 */
#include <stdlib.h>
#include <string.h>
void process_data(int len, char *src) {
    char *buf = (char*)malloc(512);
    if (!buf) return;
    if (len < 512) {
        memcpy(buf, src, 128);  /* constant write, alloc=512 */
    }
    free(buf);
}
