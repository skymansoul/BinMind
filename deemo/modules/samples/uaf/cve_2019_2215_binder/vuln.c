/*
 * CVE-2019-2215 模式复刻 — binder mmap UAF (Android)
 * 真实漏洞: binder 的 mmap 释放后 fd 仍可用, 内核 UAF → 提权
 * 触发条件: mmap 后 close 再通过 fd 访问 binder_node
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct binder_node {
    int ptr;
    int cookie;
    char name[8];
};

struct binder_proc {
    struct binder_node *nodes;
    int node_count;
    int closed;
};

void binder_release(struct binder_proc *p) {
    /* 缺陷: 释放 nodes 但未置 NULL, proc 仍可被访问 */
    free(p->nodes);
    p->closed = 1;
}

struct binder_node *find_node(struct binder_proc *p, int ptr) {
    /* 缺陷: 未检查 closed */
    int i;
    for (i = 0; i < p->node_count; i++) {
        if (p->nodes[i].ptr == ptr)   /* UAF */
            return &p->nodes[i];
    }
    return NULL;
}

int main(int argc, char **argv) {
    struct binder_proc *p = (struct binder_proc *)malloc(sizeof(*p));
    p->node_count = 1;
    p->nodes = (struct binder_node *)malloc(sizeof(struct binder_node));
    p->nodes[0].ptr = 0x1000;
    p->nodes[0].cookie = 0x2000;
    strcpy(p->nodes[0].name, "binder0");
    p->closed = 0;

    binder_release(p);
    /* UAF: close 后仍通过 proc 查找 node */
    struct binder_node *n = find_node(p, 0x1000);
    if (n) printf("node: %s\n", n->name);
    free(p);
    return 0;
}
