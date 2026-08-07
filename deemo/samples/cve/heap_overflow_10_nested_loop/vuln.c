/* heap_overflow_10: Nested loop heap overflow
 * CWE-122: buf=malloc(16); for rows for cols → total writes > alloc
 * Pattern: 2D array emulated on heap but total size computed incorrectly
 * Expected: TRUE POSITIVE (nested loop total iteration count)
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int trigger_nested_overflow(void) {
    int rows = 4, cols = 8;
    char *buf = (char *)malloc(16);  // should be rows*cols=32, but only 16 allocated
    if (!buf) return -1;
    for (int r = 0; r < rows; r++) {
        for (int c = 0; c < cols; c++) {
            buf[r * cols + c] = 'X';  // writes to buf[0..32), overflows at buf[16+]
        }
    }
    buf[31] = 0;
    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main(void) {
    return trigger_nested_overflow();
}
