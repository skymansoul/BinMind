/* UAF-TP-04: if(cond) free(p); 之后无条件 p[0] 读. */
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    (void)argv;
    char *p = (char *)malloc(16);
    if (!p) return 1;
    if (argc > 1) {
        free(p);
    }
    printf("%d\n", p[0]);
    free(p);
    return 0;
}
