#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "data");
    free(p);
    printf("[*] len=%zu\n", strlen(p));   /* UAF: strlen ½âÒıÓÃ */
    return 0;
}
