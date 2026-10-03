/*
 * CVE-2016-5195 (Dirty COW) 模式复刻 — 页缓存 COW 竞争 UAF
 * 真实漏洞: 内核 get_user_page 与 madvise 竞争导致只读映射可写,
 *           本质是页表项释放后仍被引用
 * 触发条件: 多线程写 + madvise(DONTNEED) 竞争
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cow_page {
    int refcnt;
    char data[64];
    int freed;
};

struct mm_struct {
    struct cow_page *page;
    int writable;
};

void cow_page_free(struct cow_page *p) {
    if (--p->refcnt == 0) {
        free(p);              /* 页释放 */
    }
}

int handle_mm_fault(struct mm_struct *mm) {
    /* 缺陷: COW 复制时未正确管理页引用计数 */
    struct cow_page *old = mm->page;
    struct cow_page *copy = (struct cow_page *)malloc(sizeof(*copy));
    memcpy(copy, old, sizeof(*copy));   /* 读 old (可能已释放) */
    copy->refcnt = 1;
    mm->page = copy;
    cow_page_free(old);       /* old 释放 */
    return 0;
}

int main(int argc, char **argv) {
    struct mm_struct *mm = (struct mm_struct *)malloc(sizeof(*mm));
    mm->page = (struct cow_page *)malloc(sizeof(*mm->page));
    mm->page->refcnt = 2;     /* 主映射 + 子进程映射 */
    memset(mm->page->data, 'C', 64);

    /* 竞争: 写触发 COW, 同时另一线程 madvise 释放页 */
    handle_mm_fault(mm);
    handle_mm_fault(mm);      /* 第二次 fault: 页可能已释放 */
    free(mm);
    return 0;
}
