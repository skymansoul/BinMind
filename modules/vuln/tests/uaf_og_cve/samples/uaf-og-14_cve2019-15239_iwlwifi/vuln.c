/* CVE-2019-15239 (iwlwifi) UAF 复现 — 固件命令响应释放后其
   callback 上下文仍被访问. 简化: free(p); use(p->resp). */

#include <stdio.h>
#include <stdlib.h>

struct fw_cmd {
    int resp;
    int seq;
};

int main(void) {
    struct fw_cmd *c;
    c = (struct fw_cmd *)malloc(sizeof(struct fw_cmd));
    if (!c) {
        return 1;
    }
    c->seq = 9;
    free(c);
    printf("%d\n", c->resp);
    return 0;
}
