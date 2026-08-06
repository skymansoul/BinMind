/* UAF-007: Time-of-check-time-of-use UAF pattern */
#include <stdlib.h>
#include <stdio.h>
void process(int *ptr) {
    if (ptr != NULL) {
        /* BUG: ptr could be freed by another thread here */
        printf("%d", *ptr);
    }
}
int main(void) {
    int *p = malloc(sizeof(int));
    *p = 42;
    process(p);
    free(p);
    return 0;
}
