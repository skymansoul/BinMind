#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void vuln_alloc(int count, int elem_size) {
    int total = count * elem_size;
    /* BUG: integer overflow in multiplication */
    char *buf = (char *)malloc(total);
    if (!buf) return;
    memset(buf, 0, (unsigned int)(count * elem_size));
    printf("allocated %d bytes
", total);
    free(buf);
}
int main() {
    vuln_alloc(65537, 65537);  /* 65537*65537 overflows 32-bit */
    return 0;
}
