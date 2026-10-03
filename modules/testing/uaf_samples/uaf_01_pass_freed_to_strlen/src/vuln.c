#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "data");
    free(p);
    printf("[*] len=%zu\n", strlen(p));   /* UAF: strlen 解引用 */
    return 0;
}
