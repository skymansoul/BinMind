/*
 * TP_uaf_callback_use — 回调函数中的Use-After-Free。
 *
 * 场景: free(obj)后回调函数仍持有obj指针并解引用.
 * 模拟CVE-2021-38003 (Chrome V8)的简化模式.
 * 预期: UAF检测器应检出 (TRUE POSITIVE).
 *
 * CWE-416: Use After Free
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*callback_t)(void *);

typedef struct {
    int id;
    char data[64];
    callback_t on_destroy;
} Widget;

static Widget *g_widget = NULL;

void cleanup_callback(void *ptr) {
    Widget *w = (Widget *)ptr;
    /* UAF: 此时w已被free, 但仍被回调访问 */
    printf("cleanup: id=%d data=%s\n", w->id, w->data);  /* ← UAF HERE */
}

int main() {
    Widget *w = (Widget *)malloc(sizeof(Widget));
    if (!w) return 1;
    w->id = 1;
    strcpy(w->data, "active");
    w->on_destroy = cleanup_callback;
    g_widget = w;

    /* 先调用回调, 回调中会访问w */
    w->on_destroy(w);

    free(w);  /* 释放 */

    /* 再次调用回调 → UAF */
    if (g_widget) {
        g_widget->on_destroy(g_widget);  /* ← UAF HERE */
    }

    return 0;
}
