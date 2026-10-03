/*
 * CVE-2023-32233 模式复刻 — nf_tables anonymous set UAF (内核)
 * 真实漏洞: anonymous set 释放后 nft 规则仍引用, 可提权
 * 触发条件: 创建匿名 set 后删除, 再触发规则匹配
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct nft_anon_set {
    int genmask;
    char name[8];
    void *elements;
};

struct nft_rule_ref {
    struct nft_anon_set *set;
    int gen;
};

void nft_set_destroy(struct nft_anon_set *s) {
    free(s->elements);
    free(s);                  /* 匿名 set 释放 */
}

int nft_lookup(struct nft_rule_ref *r) {
    /* 缺陷: 未检查 set 是否已随代数销毁 */
    if (r->set->genmask != r->gen)   /* UAF 读 */
        return 0;
    return r->set->elements != NULL;
}

int main(int argc, char **argv) {
    struct nft_rule_ref *r = (struct nft_rule_ref *)malloc(sizeof(*r));
    r->set = (struct nft_anon_set *)malloc(sizeof(*r->set));
    r->set->genmask = 1;
    r->set->elements = malloc(8);
    strcpy(r->set->name, "anon0");
    r->gen = 1;

    /* 代数切换销毁匿名 set */
    nft_set_destroy(r->set);

    /* UAF: 旧代规则仍引用已销毁 set */
    if (nft_lookup(r))
        printf("matched %s\n", r->set->name);
    free(r);
    return 0;
}
