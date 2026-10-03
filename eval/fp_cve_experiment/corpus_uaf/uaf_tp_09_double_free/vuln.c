/* UAF-TP-09: 同一指针两次 free. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(8);
    if (!p) return 1;
    free(p);
    free(p);
    return 0;
}
