#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

// safe_small_constants
// Type: safe
int main() {
    int a=100,b=200; char *buf=malloc(a*b);
    return 0;
}
