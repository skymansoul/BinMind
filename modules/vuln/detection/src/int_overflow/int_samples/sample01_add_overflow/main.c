#include <stdio.h>
#include <limits.h>

int main(void) {
    int x = INT_MAX;
    int y = x + 1;  /* OVERFLOW: signed wrap to INT_MIN */
    printf("INT_MAX + 1 = %d\n", y);
    return 0;
}
