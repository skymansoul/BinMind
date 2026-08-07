/* heap_fp_05: multi-path — guarded-safe path + unguarded-overflow path
 * Ensemble should KEEP (real overflow exists on the unguarded path).
 * Tests that guard correlation does NOT falsely suppress real bugs.
 */
#include <stdlib.h>
#include <string.h>
void route_message(int mode, char *msg, size_t msglen) {
    char *buf = (char*)malloc(256);
    if (!buf) return;
    if (mode == 0) {
        if (msglen > 256) return;      /* guarded path: safe */
        memcpy(buf, msg, msglen);
    } else {
        memcpy(buf, msg, msglen);       /* unguarded path: overflow! */
    }
    free(buf);
}
