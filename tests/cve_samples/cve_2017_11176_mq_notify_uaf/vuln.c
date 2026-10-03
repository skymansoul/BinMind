/* CVE-2017-11176 — Linux kernel mq_notify UAF+堆溢出
 * POSIX 消息队列通知机制中的竞态导致释放后使用, 可升级为堆溢出.
 * 类型: use_after_free / CWE-416 → CWE-122
 */
#include <stdlib.h>
#include <string.h>
typedef struct { int id; char *data; void (*cb)(void); } mq_notify_t;
static mq_notify_t *g_notify = NULL;
void trigger_uaf_heap(void) {
    g_notify = malloc(sizeof(mq_notify_t));
    g_notify->data = malloc(128);
    free(g_notify);     /* BUG: 释放后 g_notify 未置空 */
    free(g_notify->data); /* UAF: g_notify 已释放, 读其 data 字段 */
}
int main(void) { trigger_uaf_heap(); return 0; }
