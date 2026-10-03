#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    free(p);                       /* UAF: double free */
    printf("[*] done\n");
    return 0;
}
