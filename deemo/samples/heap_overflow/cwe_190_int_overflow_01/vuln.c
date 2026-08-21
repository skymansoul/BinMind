/* CWE-190: Integer overflow �� small allocation �� heap overflow */
#include <stdlib.h>
#include <string.h>

void cwe190_intof(char *src, int n) {
    int alloc_sz = n * 4;  /* may wrap to small value */
    char *buf = (char *)malloc(alloc_sz);
    if (buf) {
        memcpy(buf, src, n * 8);  /* write > alloc if n*4 overflowed */
        free(buf);
    }
}

int main(void) {
    static char src[16];
    cwe190_intof(src, 1 << 30);  /* n*4 wraps to 0, n*8 writes */
    return 0;
}
