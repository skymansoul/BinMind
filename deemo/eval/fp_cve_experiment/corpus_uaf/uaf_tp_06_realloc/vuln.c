/* UAF-TP-06: realloc 缩小后按旧偏移继续写入 (悬垂语义简化). */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "before");
    free(p);
    char *q = (char *)malloc(64);
    if (!q) return 1;
    memcpy(q, "after", 6);
    free(q);
    p[0] = 'R';
    printf("%c\n", p[0]);
    return 0;
}
