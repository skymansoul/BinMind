/* N/A 安全对照: 指针经函数返回值复活, 非 UAF. */
#include <stdio.h>
#include <stdlib.h>

static char *get_ptr(void) {
    return (char *)malloc(32);
}

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    p = get_ptr();
    printf("%s\n", p);
    free(p);
    return 0;
}
