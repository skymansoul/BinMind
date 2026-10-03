/* CVE-2016-6187 (Linux perf) UAF 复现 — probe_event 对象在
   perf_event 释放后经 tracepoint 回调被访问. 简化:
   free(p); func(p) 参数传递后解引用. */

#include <stdio.h>
#include <stdlib.h>

struct probe {
    int id;
};

static void handle(struct probe *q) {
    printf("%d\n", q->id);
}

int main(void) {
    struct probe *p;
    p = (struct probe *)malloc(sizeof(struct probe));
    if (!p) {
        return 1;
    }
    p->id = 3;
    free(p);
    handle(p);
    return 0;
}
