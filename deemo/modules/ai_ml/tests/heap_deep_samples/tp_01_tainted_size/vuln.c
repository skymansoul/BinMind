#include <string.h>
#include <stdlib.h>

__attribute__((noinline)) void process(const char *user_buf, size_t user_len) {
    char *heap = malloc(128);
    if (!heap) return;
    memcpy(heap, user_buf, user_len);   /* VULN: user_len > 128 */
    volatile char probe = heap[0];   /* 观察堆写, 防DCE */
    (void)probe;
    free(heap);
}

int main(void) {
    char big[4096];
    memset(big, 'A', sizeof(big));
    process(big, sizeof(big));
    return 0;
}
