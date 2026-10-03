/* UAF TP sample */
#include <stdlib.h>
int main(void) {
    int *p = (int *)malloc(8 * sizeof(int));
    if (!p) return -1;
    free(p);
    p[0] = 11;
    return 0;
}
