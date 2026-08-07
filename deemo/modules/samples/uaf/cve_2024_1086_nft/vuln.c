/*
 * CVE-2024-1086 模式复刻 — nf_tables use-after-free (内核, 2024 最热提权)
 * 真实漏洞: nft_verdict_init 在错误路径释放 nft_data 后仍使用
 * 触发条件: 构造含 verdict 的 nft 规则触发 double-free/UAF
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct nft_data {
    int type;
    union {
        unsigned long val;
        void *chain;
    } u;
};

struct nft_verdict {
    int code;
    struct nft_data data;
};

void nft_data_release(struct nft_data *d) {
    if (d->type == 2) {
        free(d->u.chain);     /* 释放 chain 引用 */
    }
}

int nft_verdict_init(struct nft_verdict *v, int code) {
    v->code = code;
    if (code == 1) {
        v->data.type = 2;
        v->data.u.chain = malloc(16);
        strcpy((char *)v->data.u.chain, "chain0");
        return 0;
    }
    /* 错误路径: 部分初始化后释放 */
    v->data.type = 2;
    v->data.u.chain = NULL;
    nft_data_release(&v->data);
    return -1;
}

int main(int argc, char **argv) {
    struct nft_verdict *v = (struct nft_verdict *)malloc(sizeof(*v));
    memset(v, 0, sizeof(*v));

    /* 第一次: 正常初始化, chain 分配 */
    nft_verdict_init(v, 1);
    /* 缺陷: verdict 释放时未清 data, 二次释放 → double-free */
    nft_data_release(&v->data);
    nft_data_release(&v->data);   /* double-free → UAF */
    free(v);
    return 0;
}
