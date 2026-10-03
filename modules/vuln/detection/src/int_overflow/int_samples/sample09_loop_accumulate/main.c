#include <stdio.h>
#include <limits.h>

int main(void) {
    int sum = INT_MAX - 10;
    int addends[] = {5, 5, 5, 5, 5};
    for (int i = 0; i < 5; i++) {
        sum += addends[i];  /* OVERFLOW: sum wraps at i=2 */
    }
    printf("accumulated sum = %d\n", sum);
    return 0;
}
