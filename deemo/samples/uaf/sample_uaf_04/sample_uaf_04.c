/*
 * sample_uaf_04 — UAF with reassignment (误报测试).
 *
 * free(p) 后 p = malloc(...), 然后 use(p).
 * 这是误报: p被重新分配, 指向新的合法对象.
 * CWE-416: Use After Free.
 *
 * TARPS预期: DEF_FP — S阶段检测到realloc后指针重新赋值
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "original");

    free(p);

    /* 重新分配: p不再指向已释放内存 */
    p = (char *)malloc(128);
    if (!p) return 1;
    strcpy(p, "reassigned");

    /* 这是安全的 — p指向新分配的内存 */
    p[0] = 'R';

    printf("p[0]=%c\n", p[0]);
    free(p);
    return 0;
}
