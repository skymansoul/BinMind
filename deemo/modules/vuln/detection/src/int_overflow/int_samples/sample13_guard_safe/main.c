#include <stdio.h>
#include <limits.h>
#include <stdlib.h>

int main(void) {
    int a = INT_MAX;
    int b = 10;
    /* SAFE: explicit overflow guard */
    if (a > INT_MAX - b) {
        printf("overflow prevented\n");
        return 1;
    }
    int c = a + b;
    printf("safe: %d\n", c);
    return 0;
}
