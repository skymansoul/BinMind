/* CVE-2023-0461 (Linux io_uring) UAF 复现 — 请求释放后 completion
   上下文仍被提交路径写入. 简化: free(p) 后 p->ctx 字段读取. */

#include <stdio.h>
#include <stdlib.h>

struct io_req {
    long ctx;
    int opcode;
};

int main(void) {
    struct io_req *r;
    r = (struct io_req *)malloc(sizeof(struct io_req));
    if (!r) {
        return 1;
    }
    r->opcode = 5;
    free(r);
    printf("%ld\n", r->ctx);
    return 0;
}
