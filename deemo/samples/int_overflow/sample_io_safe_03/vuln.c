/* SAFE: Constant multiplication — compiler folds, known safe
 * malloc(256 * 4) → malloc(1024) at compile time. No overflow possible.
 * EXPECT: TN
 */
#include <stdlib.h>
#include <string.h>
void safe_const_alloc(char *src) {
    int *buf = (int*)malloc(256 * sizeof(int)); /* 256*4=1024 constant */
    if (!buf) return;
    memcpy(buf, src, 256 * sizeof(int));
    free(buf);
}
