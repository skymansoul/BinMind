#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

// safe_checked_mul
// Type: safe
int main() {
    int n=1000; if(n>0xFFFFFFFF/4096)return; char *b=malloc(n*4096);
    return 0;
}
