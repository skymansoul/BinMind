#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* CVE-2022-0847 (Dirty Pipe) 模式: 简单UAF */
struct obj { char data[64]; int id; };
void process() {
    struct obj *p = malloc(sizeof(struct obj));
    p->id = 42;
    free(p);
    /* BUG: free后继续使用p */
    printf("id=%d data=%s
", p->id, p->data);
}
int main() { process(); return 0; }
