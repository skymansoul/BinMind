/* N/A 安全对照: 指针经重新 malloc 复活, 非 UAF. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    p = (char *)malloc(64);
    printf("%s\n", p);
    free(p);
    return 0;
}
