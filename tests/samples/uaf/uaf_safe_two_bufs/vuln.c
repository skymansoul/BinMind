#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-SAFE-04: 双缓冲各自使用完毕后释放, 无别名交叉、无释放后使用 */
int main(int argc, char **argv) {
    char *a = (char *)malloc(64);
    char *b = (char *)malloc(64);
    if (!a || !b) {
        free(a);
        free(b);
        return 1;
    }
    strcpy(a, "buffer-a");
    strcpy(b, "buffer-b");
    printf("%s %s\n", a, b);  /* 使用均在释放之前 */
    free(a);
    free(b);
    return 0;
}
