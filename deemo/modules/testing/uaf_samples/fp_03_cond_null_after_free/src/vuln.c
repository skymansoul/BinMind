#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    if (argc > 1) {
        free(p);
        p = NULL;                  /* 分支内置空 */
    }
    free(p);                       /* p==NULL 或未分配 — 均安全 */
    printf("[*] done\n");
    return 0;
}
