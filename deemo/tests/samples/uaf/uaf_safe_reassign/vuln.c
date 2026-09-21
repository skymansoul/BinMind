#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-SAFE-02: free 后重新分配同一指针变量, 悬垂指针被覆盖, 使用时指针指向新块 */
int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "first");
    free(p);
    p = (char *)malloc(128);  /* 重新分配, p 不再悬垂 */
    if (!p) return 1;
    strcpy(p, "second");
    printf("reassigned: %s\n", p);
    free(p);
    return 0;
}
