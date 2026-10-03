#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned long long x = 0xFFFFFFFFFFFFFF00ULL;
    x += 0x200;
    x &= 0xFFULL;
    printf("%llu\n", x);
    return 0;
}
