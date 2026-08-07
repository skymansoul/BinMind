/*
 * FP_array_index_overflow: array-style index overflow — TRUE POSITIVE.
 *
 * Pattern: buf = malloc(size); for(i=0; i<=size; i++) buf[i]=x;
 * The <= instead of < causes an off-by-one overflow.
 * The loop guard i<=size is present but the bound is WRONG (should be <).
 *
 * GAPSBV should recognize this:
 *   Stage A: finds cmp i,size+1 → guard exists but bound > alloc
 *   Stage C: interval i ∈ [0, size] → size ≥ alloc_size → overflow!
 *   Result: KEEP (correct!)
 */

#include <stdio.h>
#include <stdlib.h>

#define BUF_SIZE 64

void off_by_one(void) {
    char *buf = (char *)malloc(BUF_SIZE);
    if (!buf) return;

    /* BUG: <= instead of < → writes BUF_SIZE+1 elements */
    for (int i = 0; i <= BUF_SIZE; i++) {
        buf[i] = (char)('A' + (i % 26));
    }

    printf("buf[%d] = %c\n", BUF_SIZE - 1, buf[BUF_SIZE - 1]);
    free(buf);
}

int main(void) {
    off_by_one();
    return 0;
}
