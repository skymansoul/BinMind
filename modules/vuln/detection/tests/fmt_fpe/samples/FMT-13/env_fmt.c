
/* 格式串来自环境变量. */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *fmt = getenv("FMT");   /* 环境可控 */
    printf(fmt);
    return 0;
}
