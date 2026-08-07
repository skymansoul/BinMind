/* CVE-2025-uaf-workqueue CWE-416: 工作队列UAF — 异步任务排队后对象被提前释放, 回调执行时访问悬垂指针 */
#include <stdlib.h>
#include <string.h>

typedef void (*work_fn)(void *arg);

typedef struct WorkItem {
    work_fn callback;
    void *arg;
    struct WorkItem *next;
} WorkItem;

static WorkItem *g_queue = NULL;

/* 提交异步任务 */
void queue_work(work_fn cb, void *arg) {
    WorkItem *w = malloc(sizeof(WorkItem));
    w->callback = cb;
    w->arg = arg;
    w->next = g_queue;
    g_queue = w;
}

/* BUG: 取消任务时仅释放WorkItem, 不检查arg是否仍有效 */
void cancel_work(work_fn cb) {
    WorkItem *prev = NULL, *cur = g_queue;
    while (cur) {
        if (cur->callback == cb) {
            if (prev) prev->next = cur->next;
            else g_queue = cur->next;
            free(cur);
            return;
        }
        prev = cur;
        cur = cur->next;
    }
}

/* 刷新工作队列 */
void flush_work(void) {
    WorkItem *cur = g_queue;
    while (cur) {
        WorkItem *next = cur->next;
        cur->callback(cur->arg);
        free(cur);
        cur = next;
    }
    g_queue = NULL;
}

/* 写入回调 */
void write_callback(void *arg) {
    char *buf = (char *)arg;
    /* UAF: buf可能已在cancel_work中被释放 */
    strcpy(buf, "HACKED");
}

int trigger_uaf(void) {
    char *buf = malloc(256);
    strcpy(buf, "safe_data");

    /* 提交异步写入任务 */
    queue_work(write_callback, buf);

    /* BUG: 在任务执行前释放buf */
    free(buf);

    /* 工作队列刷新时回调访问已释放的buf → UAF */
    flush_work();
    return 0;
}

int main() {
    trigger_uaf();
    return 0;
}
