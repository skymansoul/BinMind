/* CWE-122: Heap-based Buffer Overflow �� linear index */
#include <stdlib.h>

void cwe122_linear(int user_idx, char val) {
    char *buf = (char *)malloc(64);
    if (buf) {
        buf[user_idx] = val;  /* user_idx unguarded �� OVERFLOW risk */
        free(buf);
    }
}

int main(void) {
    cwe122_linear(100, 'X');  /* 100 > 64 */
    return 0;
}
