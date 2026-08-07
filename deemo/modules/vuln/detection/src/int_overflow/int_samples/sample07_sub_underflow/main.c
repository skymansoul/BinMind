#include <stdio.h>
#include <limits.h>

int main(void) {
    int x = INT_MIN;
    int y = x - 1;  /* UNDERFLOW: signed wrap to INT_MAX */
    printf("INT_MIN - 1 = %d\n", y);
    return 0;
}
