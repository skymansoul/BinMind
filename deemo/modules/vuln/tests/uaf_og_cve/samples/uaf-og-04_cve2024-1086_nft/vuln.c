/* CVE-2024-1086 (Linux nf_tables) UAF 复现 — nft_verdict_init 中
   规则对象释放后 drop 链继续访问. 简化: free(p); use 前经
   条件分支仍访问 p->tag. */

#include <stdio.h>
#include <stdlib.h>

struct rule {
    int tag;
    int len;
};

int main(int argc, char **argv) {
    struct rule *p;
    p = (struct rule *)malloc(sizeof(struct rule));
    if (!p) {
        return 1;
    }
    p->tag = 1;
    p->len = 4;
    free(p);
    if (argc > 1) {
        printf("%d\n", p->tag);
    }
    return 0;
}
