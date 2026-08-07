#include <stdio.h>

int main(void) {
    int a = 0x40000000;  /* 1073741824 */
    int b = 4;
    int c = a * b;  /* OVERFLOW: 0x100000000 → truncated to 0 */
    printf("0x40000000 * 4 = %d (0x%x)\n", c, c);
    return 0;
}
