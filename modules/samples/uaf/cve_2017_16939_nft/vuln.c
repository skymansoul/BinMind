/*
 * CVE-2017-16939 模式复刻 — nf_tables set UAF
 * 真实漏洞: 内核 nft_set 释放后仍被 rule 引用, 可提权
 * 触发条件: 先 delset 后继续遍历引用该 set 的 rule
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct nft_set {
    char name[16];
    int refcnt;
    void *data;
};

struct nft_rule {
    struct nft_set *set;    /* 指向 set, 引用计数未管理 */
    int verdict;
};

void nft_set_destroy(struct nft_set *s) {
    free(s->data);
    free(s);                /* set 释放, 但 rule 仍引用 */
}

int main(int argc, char **argv) {
    struct nft_set *set = (struct nft_set *)malloc(sizeof(*set));
    set->data = malloc(64);
    memset(set->data, 0, 64);
    strcpy(set->name, "blacklist");
    set->refcnt = 0;

    struct nft_rule *rule = (struct nft_rule *)malloc(sizeof(*rule));
    rule->set = set;        /* 缺陷: 未增加 set 引用计数 */
    rule->verdict = 1;

    /* 用户删除 set, 但 rule 仍存活 */
    nft_set_destroy(set);

    /* UAF: 遍历 rule 时解引用已释放的 set */
    if (rule->set && rule->set->refcnt == 0) {
        printf("set %s\n", rule->set->name);
    }
    free(rule);
    return 0;
}
