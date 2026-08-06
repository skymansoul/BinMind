/* UAF-001: Classic use-after-free — free后继续通过全局指针访问 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct obj { char data[32]; void (*cb)(void); };
static struct obj *g_obj = NULL;
void safe_cb(void) { printf("safe\n"); }
int main() {
    g_obj = malloc(sizeof(struct obj));
    g_obj->cb = safe_cb;
    free(g_obj);              /* FREE */
    /* UAF: g_obj still used below — dangling pointer */
    g_obj->cb();              /* USE AFTER FREE */
    return 0;
}
