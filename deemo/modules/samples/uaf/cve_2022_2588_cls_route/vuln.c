/*
 * CVE-2022-2588 模式复刻 — cls_route UAF (内核 tc)
 * 真实漏洞: cls_route filter 释放后仍被引用, 可本地提权
 * 触发条件: filter 删除后仍经 prio 链表访问
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cls_route_filter {
    int prio;
    int handle;
    struct cls_route_filter *next;
    void *exts;
};

void cls_route_destroy(struct cls_route_filter *f) {
    free(f->exts);
    free(f);                  /* filter 释放 */
}

int cls_route_walk(struct cls_route_filter *head) {
    /* 缺陷: 遍历时 filter 可能已释放 */
    int count = 0;
    struct cls_route_filter *f = head;
    while (f) {
        count += f->handle;   /* UAF 读 */
        f = f->next;
    }
    return count;
}

int main(int argc, char **argv) {
    struct cls_route_filter *f1 =
        (struct cls_route_filter *)malloc(sizeof(*f1));
    f1->prio = 1;
    f1->handle = 100;
    f1->exts = malloc(16);
    f1->next = NULL;

    /* 删除 filter 后链表头仍指向已释放对象 */
    cls_route_destroy(f1);
    printf("walk: %d\n", cls_route_walk(f1));   /* UAF */
    return 0;
}
