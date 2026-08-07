/* UAF TP sample */
#include <stdlib.h>
int main(void) {
    int *p = (int *)malloc(sizeof(int));
    if (!p) return -1;
    free(p);
    *p = 10;
    return 0;
}
