/*
 * CVE-2022-0847 (Dirty Pipe) 模式复刻 — 管道页缓存 UAF 数据注入
 * 真实漏洞: 内核管道 splice 后页缓存引用未失效, 可写只读文件
 * 触发条件: splice 半满管道页后写, 命中已释放的页缓存
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct pipe_buffer {
    int offset;
    int len;
    void *page;               /* 页缓存引用 */
    int flags;
};

struct pipe_inode {
    struct pipe_buffer bufs[16];
    int nrbufs;
};

void pipe_free_page(struct pipe_buffer *b) {
    /* 模拟页缓存释放 */
    free(b->page);
    b->flags = 0;
}

int pipe_write(struct pipe_inode *pipe, const char *data, int len) {
    struct pipe_buffer *b = &pipe->bufs[0];
    /* 缺陷: 未检查 b->flags (页缓存是否有效) */
    if (b->len > 0) {
        memcpy(b->page, data, len);   /* UAF 写: 页缓存已释放 */
    }
    return len;
}

int main(int argc, char **argv) {
    struct pipe_inode *pipe = (struct pipe_inode *)malloc(sizeof(*pipe));
    pipe->nrbufs = 1;
    pipe->bufs[0].offset = 0;
    pipe->bufs[0].len = 4096;
    pipe->bufs[0].flags = 1;
    pipe->bufs[0].page = malloc(4096);
    memset(pipe->bufs[0].page, 0, 4096);

    /* 模拟 splice 后半满页 + 页缓存被回收 */
    pipe->bufs[0].len = 1;
    pipe_free_page(&pipe->bufs[0]);

    /* Dirty Pipe: 写 1 字节到"已释放"的页缓存 */
    pipe_write(pipe, "A", 1);
    free(pipe);
    return 0;
}
