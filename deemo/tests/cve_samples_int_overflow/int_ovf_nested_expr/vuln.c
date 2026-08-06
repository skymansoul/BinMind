#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

// int_ovf_nested_expr
// Type: int_overflow
int main() {
    int len=0x7FFFFFFF,off=4; char *buf=malloc((len+off)*sizeof(void*));
    return 0;
}
