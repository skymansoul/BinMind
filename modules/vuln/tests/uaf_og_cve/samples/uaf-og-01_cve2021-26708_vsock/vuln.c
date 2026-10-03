/* CVE-2021-26708 (Linux vsock) UAF 复现 — transport 指针在释放后仍被
   使用: free(t) 后经容器访问 t->ops. 简化: free(p) 后解引用 p->field. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct obj {
    int kind;
    char name[16];
};

int main(void) {
    struct obj *p;
    p = (struct obj *)malloc(sizeof(struct obj));
    if (!p) {
        return 1;
    }
    p->kind = 1;
    free(p);
    printf("%d\n", p->kind);
    return 0;
}
