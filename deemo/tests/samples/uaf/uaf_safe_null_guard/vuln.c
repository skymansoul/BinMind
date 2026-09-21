#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-SAFE-03: free 后立即置 NULL, 后续判空提前返回, 全程无悬垂解引用 */
int main(int argc, char **argv) {
    char *p = (char *)malloc(128);
    if (!p) return 1;
    strcpy(p, "data");
    printf("payload: %s\n", p);
    free(p);
    p = NULL;              /* 置空消除悬垂指针 */
    if (!p) return 0;      /* 判空即返回, 不存在解引用路径 */
    return 0;
}
