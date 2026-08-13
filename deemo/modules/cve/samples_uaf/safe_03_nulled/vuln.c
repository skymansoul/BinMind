/* N/A 安全对照: free 后置空并在守卫内使用, 非 UAF. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    p = NULL;
    if (p) printf("%s\n", p);
    return 0;
}
