/*
 * CVE-2021-22555 模式复刻 — netfilter UAF (内核, 经典提权链)
 * 真实漏洞: nf_tables 释放 set 后 rule 仍引用, 堆越界+UAF
 * 触发条件: 用户态构造 nft 规则触发 use-after-free
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct nft_expr {
    int op;
    struct nft_set *set;
    char data[16];
};

struct nft_set {
    int refcnt;
    char name[8];
};

struct nft_rule {
    struct nft_expr *exprs;
    int nelems;
};

void nft_expr_destroy(struct nft_expr *e) {
    if (e->set) {
        if (--e->set->refcnt == 0)
            free(e->set);     /* set 释放 */
    }
}

void nft_rule_release(struct nft_rule *r) {
    int i;
    for (i = 0; i < r->nelems; i++)
        nft_expr_destroy(&r->exprs[i]);
}

int main(int argc, char **argv) {
    struct nft_rule *rule = (struct nft_rule *)malloc(sizeof(*rule));
    rule->nelems = 1;
    rule->exprs = (struct nft_expr *)malloc(sizeof(struct nft_expr));
    rule->exprs[0].op = 1;
    rule->exprs[0].set = (struct nft_set *)malloc(sizeof(struct nft_set));
    rule->exprs[0].set->refcnt = 0;
    strcpy(rule->exprs[0].set->name, "s0");

    /* 缺陷: expr 被两处引用 (rule + 外部), 释放一次即 UAF */
    struct nft_set *alias = rule->exprs[0].set;
    nft_rule_release(rule);   /* set 释放 */
    if (alias->refcnt == 0)   /* UAF 读 */
        printf("set %s\n", alias->name);
    free(rule->exprs);
    free(rule);
    return 0;
}
