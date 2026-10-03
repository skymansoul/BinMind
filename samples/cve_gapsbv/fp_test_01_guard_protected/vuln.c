/* FP-TEST-01: if-guarded write — should be filtered by Stage A/B.
 * malloc(64) + if (size < 64) memcpy(buf, src, size) — always safe.
 * Stage A (guard_inference) should detect the cmp+jcc pattern and FILTER.
 */
#include <stdlib.h>
#include <string.h>

void process_data(int user_size) {
    char *buf = (char *)malloc(64);
    if (buf == NULL) return;
    /* guard: size must be < 64 to enter the write path */
    if (user_size < 64) {
        memcpy(buf, "safe_data", user_size);
    }
    free(buf);
}

int main(void) {
    process_data(32);
    return 0;
}
