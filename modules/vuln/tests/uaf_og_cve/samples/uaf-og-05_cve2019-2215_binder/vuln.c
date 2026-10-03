/* CVE-2019-2215 (Android binder) UAF 复现 — proc 释放后文件描述符
   的 refcount 操作仍经 release 回调访问对象. 简化: free(p) 后
   atomic_dec(&p->refcnt). */

#include <stdio.h>
#include <stdlib.h>

struct binder_proc {
    int refcnt;
    int pid;
};

int main(void) {
    struct binder_proc *p;
    p = (struct binder_proc *)malloc(sizeof(struct binder_proc));
    if (!p) {
        return 1;
    }
    p->refcnt = 1;
    free(p);
    p->refcnt -= 1;
    return 0;
}
