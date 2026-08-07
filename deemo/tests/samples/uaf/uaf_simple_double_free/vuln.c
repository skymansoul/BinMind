#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-01: free后直接使用 — 最简UAF模式 */
int main(int argc, char **argv) {
    char *p = (char *)malloc(128);
    if (!p) return 1;
    strcpy(p, "sensitive_data");
    free(p);
    printf("use after free: %s\n", p);  /* VULNERABLE */
    return 0;
}
