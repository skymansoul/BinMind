/* guard checks one bound but write uses another variable */
#include <stdlib.h>

void edge_partial_guard(int idx, int size, char val) {
    char *buf = (char *)malloc(64);
    if (buf && idx < 64) {
        buf[size] = val;  /* size is unguarded �� could overflow */
    }
    free(buf);
}

int main(void) {
    edge_partial_guard(0, 100, 'R');  /* size=100 > 64, unguarded */
    return 0;
}
