#include <stdio.h>

int main(void) {
    unsigned int x = 0x40000000;
    unsigned int y = x << 2;  /* OVERFLOW: bit 30→32 = 0 in 32-bit */
    printf("0x40000000 << 2 = 0x%x\n", y);
    return 0;
}
