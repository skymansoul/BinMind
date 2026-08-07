/*
 * CVE-2023-0386 模式复刻 — overlayfs UAF (内核)
 * 真实漏洞: ovl_copy_up 释放 dentry 后仍使用, 可提权
 * 触发条件: FUSE 文件操作竞争导致 dentry UAF
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ovl_dentry {
    char name[16];
    int flags;
    void *inode;
};

struct ovl_copy_ctx {
    struct ovl_dentry *upper;
    int done;
};

void ovl_dentry_release(struct ovl_dentry *d) {
    free(d->inode);
    free(d);                  /* dentry 释放 */
}

int ovl_do_copy(struct ovl_copy_ctx *ctx) {
    /* 缺陷: 拷贝完成后 upper dentry 未保留引用计数 */
    ovl_dentry_release(ctx->upper);
    ctx->done = 1;
    return 0;
}

int ovl_lookup_upper(struct ovl_copy_ctx *ctx) {
    /* 缺陷: done 后仍访问 upper */
    if (ctx->done)
        return ctx->upper->flags;   /* UAF 读 */
    return 0;
}

int main(int argc, char **argv) {
    struct ovl_copy_ctx *ctx = (struct ovl_copy_ctx *)malloc(sizeof(*ctx));
    ctx->upper = (struct ovl_dentry *)malloc(sizeof(*ctx->upper));
    ctx->upper->inode = malloc(32);
    ctx->upper->flags = 0x1;
    strcpy(ctx->upper->name, "upper");
    ctx->done = 0;

    ovl_do_copy(ctx);
    printf("flags: %d\n", ovl_lookup_upper(ctx));   /* UAF */
    free(ctx);
    return 0;
}
