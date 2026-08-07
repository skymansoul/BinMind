/* uaf_11_member_read — free 后读成员 (TP)。
 * Expected: UAF */
#include <stdlib.h>

typedef struct { int len; char data[16]; } H;

int main(void) {
    H *h = (H *)malloc(sizeof(H));
    if (!h) return 1;
    free(h);
    return h->len;                /* UAF read */
}
