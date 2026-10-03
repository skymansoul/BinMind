/* UAF-005: Double free in cleanup path */
#include <stdlib.h>
void cleanup(char *a, char *b) {
    free(a);
    free(b);
    free(a); /* BUG: double free of a */
}
int main(void) {
    cleanup(malloc(32), malloc(64));
    return 0;
}
