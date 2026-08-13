#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void cleanup(char *p) {
    if (!p) return;
    free(p);
}
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "temp");
    cleanup(p);                      /* p 被释放 */
    printf("[*] done\n");            /* 之后不使用 p */
    return 0;
}
