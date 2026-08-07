/* 嵌套分配堆溢出 (通用模式 — 多层分配后混淆大小)
 *
 * 触发条件: 外层分配 inner_buf = malloc(inner_size),
 * 内层进行 memset(inner_buf, ..., outer_size) 混淆了大小。
 *
 * 测试目标: 跨调用点的 size 追踪 — 需要区分 inner 和 outer
 * 分配的大小, 这对别名分析提出了要求。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct container {
    char *inner;
    size_t inner_size;
    size_t outer_size;
};

static int init_container(struct container *c, size_t n_inner, size_t n_outer) {
    c->inner_size = n_inner;
    c->outer_size = n_outer;

    c->inner = (char *)malloc(c->inner_size);
    if (!c->inner) return -1;

    /* BUG: 使用了 outer_size 而非 inner_size, 可能溢出 */
    memset(c->inner, 0, c->outer_size);
    return 0;
}

int main(int argc, char **argv) {
    struct container c;
    size_t inner_sz = 64;
    size_t outer_sz = (argc >= 2) ? (size_t)atoi(argv[1]) : 64;
    /* 若 outer_sz > inner_sz → 溢出 */
    init_container(&c, inner_sz, outer_sz);
    free(c.inner);
    return 0;
}
