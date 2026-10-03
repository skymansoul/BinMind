/* CVE-2022-1011 (Linux aio poll) UAF 复现 — aio_poll 请求完成
   回调释放后, 请求对象仍被取消路径访问. 简化: free(p) 后
   use(p->wait). */

#include <stdio.h>
#include <stdlib.h>

struct poll_req {
    int wait;
    int events;
};

int main(void) {
    struct poll_req *r;
    r = (struct poll_req *)malloc(sizeof(struct poll_req));
    if (!r) {
        return 1;
    }
    r->events = 1;
    free(r);
    r->wait = 0;
    return 0;
}
