/*
 * UAF Cross-Function Free 样本
 *
 * 模式: void cleanup(T *p) { free(p); }
 * 调用: cleanup(data); ... data->field = ... → UAF (现有检测器漏检)
 *
 * 与 uaf_callback_free 的全局别名模式互补:
 *   - uaf_callback_free: func(ptr) → g_var = param → free(ptr) → use(g_var)
 *   - cross_func_free:   func(ptr) → free(param in func body) → use(ptr after call)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Node {
    int id;
    char name[32];
    struct Node *next;
} Node;

/* ── 跨函数 free 模式: 回调/辅助函数内部释放参数 ── */

/* 模式1: void cleanup(T *p) { free(p); } — 最简形式 */
void cleanup(Node *p) {
    if (p != NULL) {
        free(p);
    }
}

/* 模式2: 多个参数, 释放其中一个 */
void release_resources(int fd, Node *obj, char *buf) {
    close(fd);
    free(obj);   /* ← 参数 obj 被释放 */
    free(buf);   /* ← 参数 buf 也被释放 */
}

int main(void) {
    Node *data = (Node *)malloc(sizeof(Node));
    data->id = 1;
    /* ── 跨函数释放 (模式1) ── */
    cleanup(data);
    /* BUG: 释放后使用 — free() 隐藏在 cleanup() 内部 */
    data->id = 42;           /* line 39 — UAF#1: cleanup内free后写入 */

    /* ── 跨函数释放 (模式2) — 多参数, 释放第二个 ── */
    Node *obj = (Node *)malloc(sizeof(Node));
    char *extra = (char *)malloc(128);
    obj->id = 10;
    release_resources(-1, obj, extra);
    /* BUG: obj 已被 release_resources 内部释放 */
    obj->next = NULL;        /* line 47 — UAF#2 */
    /* extra 也被释放了 */
    strcpy(extra, "leak");   /* line 49 — UAF#3 */

    /* ── 安全对比: 自己调用 free 后再用 — 现有检测器可覆盖 ── */
    Node *safe = (Node *)malloc(sizeof(Node));
    free(safe);
    safe->id = 0;            /* line 54 — UAF#4: 传统模式 (已有覆盖) */

    return 0;
}
