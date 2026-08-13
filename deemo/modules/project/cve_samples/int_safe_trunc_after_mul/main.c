#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned long long a = 0x100000000000000ULL;
    unsigned long long b = a * 0x100ULL;
    unsigned char c = (unsigned char)b;
    printf("%u\n", c);
    return 0;
}
