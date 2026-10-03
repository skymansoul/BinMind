/*
 * CVE-2021-4204 模式复刻 — eBPF verifier UAF (内核)
 * 真实漏洞: 内核 eBPF verifier 在指针运算校验中释放 map 后
 *           仍引用, 可本地提权
 * 触发条件: 构造含指针运算的 BPF 程序触发 verifier 错误路径
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct bpf_map {
    int refcnt;
    char name[8];
    void *values;
};

struct bpf_reg {
    int type;
    struct bpf_map *map_ptr;
    int off;
};

void bpf_map_put(struct bpf_map *m) {
    if (--m->refcnt == 0) {
        free(m->values);
        free(m);              /* map 释放 */
    }
}

int check_ptr_off(struct bpf_reg *reg, int off) {
    /* 缺陷: 错误路径释放 map 引用后仍返回 reg->map_ptr */
    if (off < 0 || off > 64) {
        bpf_map_put(reg->map_ptr);   /* 释放引用 */
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    struct bpf_map *m = (struct bpf_map *)malloc(sizeof(*m));
    m->refcnt = 1;
    m->values = malloc(128);
    strcpy(m->name, "map0");

    struct bpf_reg reg;
    reg.type = 1;
    reg.map_ptr = m;
    reg.off = 0;

    /* verifier 错误路径: 释放后 reg 仍被后续使用 */
    if (check_ptr_off(&reg, 100) < 0) {
        /* UAF: reg.map_ptr 已随 refcnt-- 释放 (refcnt=0) */
        printf("map %s\n", reg.map_ptr->name);
    }
    free(m);
    return 0;
}
