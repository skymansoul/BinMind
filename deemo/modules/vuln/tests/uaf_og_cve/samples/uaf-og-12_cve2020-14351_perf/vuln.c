/* CVE-2020-14351 (Linux perf) UAF 复现 — perf_event 释放后
   event->ctx 在调度回调中被解引用. 简化: free(p) 后 *p 写入. */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    long *p;
    p = (long *)malloc(32);
    if (!p) {
        return 1;
    }
    *p = 0x10;
    free(p);
    *p = 0x20;
    return 0;
}
