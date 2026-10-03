/* CVE-2018-9568 (Android binder) UAF 复现 — binder_thread 释放后
   waitqueue 唤醒仍引用该线程. 简化: free(p); use(p->wait). */

#include <stdio.h>
#include <stdlib.h>

struct thread {
    int wait;
    int pid;
};

int main(void) {
    struct thread *t;
    t = (struct thread *)malloc(sizeof(struct thread));
    if (!t) {
        return 1;
    }
    t->wait = 0;
    free(t);
    t->wait = 1;
    return 0;
}
