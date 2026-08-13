#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned long long x = 0xFFFFFFFFFFFFFFF0ULL;
    x += 0x20;
    x >>= 4;
    printf("%llu\n", x);
    return 0;
}
