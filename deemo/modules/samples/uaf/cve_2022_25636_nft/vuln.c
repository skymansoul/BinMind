/*
 * CVE-2022-25636 模式复刻 — nf_tables 越界写 + UAF (内核)
 * 真实漏洞: nft_byteorder 在错误代数引用已释放的 set, 堆越界
 * 触发条件: 构造 byteorder 规则触发旧代 set 引用
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct nft_byteorder {
    int gen;
    struct nft_data *data;
    int nelems;
};

struct nft_data {
    unsigned long val;
};

void nft_data_destroy(struct nft_data *d) {
    free(d);                  /* 数据释放 */
}

int nft_byteorder_eval(struct nft_byteorder *bo) {
    /* 缺陷: 未校验代数, 引用可能已释放的 data */
    int i;
    for (i = 0; i < bo->nelems; i++) {
        bo->data[i].val = __builtin_bswap64(bo->data[i].val);
        /* UAF 写: data 可能已随旧代销毁 */
    }
    return 0;
}

int main(int argc, char **argv) {
    struct nft_byteorder *bo =
        (struct nft_byteorder *)malloc(sizeof(*bo));
    bo->gen = 1;
    bo->nelems = 2;
    bo->data = (struct nft_data *)malloc(2 * sizeof(struct nft_data));
    bo->data[0].val = 0x11223344;
    bo->data[1].val = 0x55667788;

    /* 代数切换: 数据释放但规则仍存活 */
    nft_data_destroy(bo->data);
    bo->data = NULL;
    bo->gen = 2;

    /* UAF: 规则重新匹配时 data 未重建 */
    if (bo->gen == 2 && bo->data) {
        nft_byteorder_eval(bo);
    }
    free(bo);
    return 0;
}
