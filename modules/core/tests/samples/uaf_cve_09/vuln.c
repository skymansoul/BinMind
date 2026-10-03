// CVE-2020-6418: Global pointer UAF
#include <stdlib.h>

typedef struct ctx { int refs; void *data; } Ctx;
static Ctx *g_ctx = NULL;                // global pointer

Ctx* get_ctx() {
    if (!g_ctx) {
        g_ctx = (Ctx*)malloc(sizeof(Ctx));  // @uaf_alloc
        g_ctx->refs = 1;
    }
    return g_ctx;
}

void cleanup_ctx() {
    free(g_ctx);                           // @uaf_free
    // Bug: g_ctx not set to NULL
}

int vuln_global_uaf() {
    Ctx *c = get_ctx();
    cleanup_ctx();
    int r = c->refs;                       // @uaf_use — UAF via cached ptr
    return r;
}
int main() { vuln_global_uaf(); return 0; }