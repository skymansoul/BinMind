/* UAF TP sample */
#include <stdlib.h>
int main(void) {
    int *old = (int *)malloc(8);
    if (!old) return -1;
    int *newp = (int *)realloc(old, 64);
    if (!newp) return -1;
    old[0] = 13;
    return 0;
}
