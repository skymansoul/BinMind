#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-SAFE-01: 所有使用均在 free 之前完成, free 后不再触碰指针 */
int main(int argc, char **argv) {
    char *p = (char *)malloc(128);
    if (!p) return 1;
    strcpy(p, "sensitive_data");
    printf("use before free: %s\n", p);
    free(p);  /* 最后一次使用之后才释放 */
    return 0;
}
