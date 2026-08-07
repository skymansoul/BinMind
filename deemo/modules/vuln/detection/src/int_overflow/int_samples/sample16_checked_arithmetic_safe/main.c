#include <stdio.h>
#include <limits.h>

int main(void) {
    int a = INT_MAX;
    int b = 1;
    int result;
    /* SAFE: compiler builtin overflow detection */
    if (__builtin_add_overflow(a, b, &result)) {
        printf("overflow detected by builtin\n");
        return 1;
    }
    printf("result: %d\n", result);
    return 0;
}
