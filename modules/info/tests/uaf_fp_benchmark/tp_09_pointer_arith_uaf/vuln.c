/* UAF TP sample */
#include <stdlib.h>
int main(void) {
    int *p = (int *)malloc(16 * sizeof(int));
    if (!p) return -1;
    free(p);
    p[2] = 9;
    return 0;
}
