/*
 * TP_path_condition_guard: write protected by a path condition.
 *
 * Pattern:
 *   if (idx >= size) return;
 *   buf[idx] = value;
 *
 * The guard is NOT immediately adjacent (different from TP_guarded_write
 * where if wraps the write). Instead, the guard is an early-return:
 * if the index is too large, the function exits. The write only executes
 * on the path where idx < size. GAPSBV's path condition tracker (Stage B)
 * should propagate the constraint idx < size to the block containing the write.
 *
 * Reference: common pattern in kernel code (early error returns).
 */

#include <stdio.h>
#include <stdlib.h>

void guarded_by_return(size_t idx, const char *data, size_t data_len) {
    char *buf = (char *)malloc(64);
    if (!buf) return;

    /* Early return guards: the write below only executes if idx < 64 */
    if (idx >= 64)
        return;

    if (idx + data_len > 64)
        data_len = 64 - idx;

    /* This write is on the path where idx < 64 */
    for (size_t i = 0; i < data_len; i++) {
        buf[idx + i] = data[i];
    }

    printf("buf[%zu] = %c\n", idx, buf[idx]);
    free(buf);
}

int main(int argc, char **argv) {
    size_t idx = (argc > 1) ? (size_t)atoi(argv[1]) : 10;
    char data[] = "hello";
    guarded_by_return(idx, data, sizeof(data));
    return 0;
}
