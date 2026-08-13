/* N/A 安全对照: free 位于错误分支, 正常路径使用, 路径互斥. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    if (argc < 2) {
        free(p);
        return 1;
    }
    printf("%s\n", p);
    free(p);
    return 0;
}
