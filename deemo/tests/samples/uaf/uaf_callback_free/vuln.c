#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF-08: 回调中的UAF — free后仍注册为callback被调用 */
typedef void (*cb_t)(void *);
static cb_t g_callback = NULL;
static void *g_ctx = NULL;
void register_cb(cb_t cb, void *ctx) { g_callback = cb; g_ctx = ctx; }
void my_handler(void *ctx) { printf("handler: %s\n", (char *)ctx); }

int main(void) {
    char *data = (char *)malloc(64);
    if (!data) return 1;
    strcpy(data, "callback_context");
    register_cb(my_handler, data);
    free(data);  /* 释放context但未取消注册 */
    if (g_callback) g_callback(g_ctx);  /* VULNERABLE: g_ctx已释放 */
    return 0;
}
