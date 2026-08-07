/* UAF TN (safe) sample */
#include <stdlib.h>
int main(void) {
    int *p = (int *)malloc(8 * sizeof(int));
    if (!p) return -1;
    free(p);
    if (p == NULL) { return 1; }
    return 0;
}
