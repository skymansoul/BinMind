/* UAF-05: Double free (TP) */
#include <stdlib.h>

void cleanup(char *a, char *b) {
    free(a);
    free(b);
    free(a);  /* BUG: double free of a */
}

int main(void) {
    cleanup((char *)malloc(32), (char *)malloc(64));
    return 0;
}
