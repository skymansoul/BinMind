/* UAF TN (safe) sample */
#include <stdlib.h>
int main(void) {
    void *p = malloc(16);
    if (!p) return -1;
    free(p);
    return 0;
}
