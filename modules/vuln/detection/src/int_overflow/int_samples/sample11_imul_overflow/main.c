#include <stdio.h>
#include <limits.h>

int checked_multiply(int a, int b, int *result) {
    /* naive check misses edge cases */
    if (a > 0 && b > 0 && a > INT_MAX / b) {
        return 0;  /* overflow detected */
    }
    *result = a * b;  /* OVERFLOW: may still overflow for negative */
    return 1;
}

int main(void) {
    int result;
    int ok = checked_multiply(INT_MIN, -1, &result);
    printf("checked: %d, result: %d\n", ok, result);
    return 0;
}
