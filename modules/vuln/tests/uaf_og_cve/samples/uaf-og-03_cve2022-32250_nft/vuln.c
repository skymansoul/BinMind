/* CVE-2022-32250 (Linux nf_tables) UAF 复现 — nft_chain 释放后其
   expr 指针经 hook 回调被再次使用. 简化: free(p); use(p->next). */

#include <stdio.h>
#include <stdlib.h>

struct node {
    struct node *next;
    int v;
};

int main(void) {
    struct node *p;
    p = (struct node *)malloc(sizeof(struct node));
    if (!p) {
        return 1;
    }
    p->v = 7;
    free(p);
    printf("%d\n", p->v);
    return 0;
}
