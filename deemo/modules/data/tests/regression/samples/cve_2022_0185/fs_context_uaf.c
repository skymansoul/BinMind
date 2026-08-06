/* CVE-2022-0185 — Linux kernel fs_context UAF
   Type: use_after_free
   gcc -O0 fs_context_uaf.c -o fs_context_uaf

   Original: filesystem context object freed prematurely during
   legacy parameter parsing in the kernel. Simplified: a config
   parser frees a struct then accesses it later. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *source;
    char *options;
    int refcount;
} FSContext;

static FSContext *g_ctx = NULL;

FSContext *alloc_fs_context(const char *src) {
    FSContext *ctx = (FSContext *)malloc(sizeof(FSContext));
    ctx->source = strdup(src);
    ctx->options = NULL;
    ctx->refcount = 1;
    return ctx;
}

void put_fs_context(FSContext *ctx) {
    if (ctx && --ctx->refcount <= 0) {
        free(ctx->source); free(ctx->options); free(ctx);
    }
}

/* VULNERABLE: frees context on error path, then uses it later */
int parse_legacy_option(FSContext *ctx, const char *opt) {
    if (!opt || !*opt) {
        put_fs_context(ctx);  /* BUG: frees ctx on early return */
        return -1;
    }
    /* UAF: ctx may have been freed by put_fs_context above */
    ctx->options = strdup(opt);
    return 0;
}

int main() {
    FSContext *ctx = alloc_fs_context("/dev/sda1");
    parse_legacy_option(ctx, NULL);  /* triggers free */
    parse_legacy_option(ctx, "ro");  /* UAF on freed ctx */
    return 0;
}
