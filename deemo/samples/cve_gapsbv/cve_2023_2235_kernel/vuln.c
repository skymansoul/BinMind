/*
 * CVE-2023-2235 — Linux kernel: perf_event 堆溢出 (CWE-122)
 *
 * Linux kernel 6.2.3 之前: perf_event_open() 的
 * perf_group_detach() 在组事件分离时存在引用计数问题,
 * 导致 perf_buffer 被过早释放, 后续写入造成堆损坏.
 *
 * 具体: attach/detach 竞态中的 AUX 缓冲区释放复用.
 *
 * CVSS: 7.0 (High), CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define PERF_AUX_SIZE 0x10000  /* 64KB AUX buffer */

typedef struct {
    uint8_t *aux_buf;
    size_t aux_size;
    size_t aux_head;
    int ref_count;
} perf_event;

static perf_event *g_leader = NULL;

void perf_aux_output_begin(perf_event *ev, size_t size) {
    /* [VULN] 未检查 ev->aux_buf 是否仍然有效 */
    if (ev->aux_head + size > ev->aux_size) {
        ev->aux_head = 0; /* 回绕 */
    }
    /* 继续写入 — aux_buf 可能已在另一个 CPU 上被释放 */
    memset(ev->aux_buf + ev->aux_head, 0xBB, size); /* ← UAF/溢出 */
    ev->aux_head += size;
}

void perf_group_detach(perf_event *child) {
    /* 减少引用计数, 可能触发释放 */
    child->ref_count--;
    if (child->ref_count <= 0 && child->aux_buf) {
        free(child->aux_buf);  /* ← [VULN] leader 可能还在用 */
        child->aux_buf = NULL;
        child->aux_size = 0;
    }
}

int main(void) {
    perf_event leader;
    perf_event child;

    leader.aux_buf = (uint8_t *)malloc(PERF_AUX_SIZE);
    leader.aux_size = PERF_AUX_SIZE;
    leader.aux_head = 0;
    leader.ref_count = 1;

    child.aux_buf = leader.aux_buf; /* 共享 AUX 缓冲区 */
    child.aux_size = PERF_AUX_SIZE;
    child.aux_head = 0;
    child.ref_count = 1;

    g_leader = &leader;

    /* 模拟竞态: CPU0 正在输出, CPU1 分离了子事件 */
    perf_aux_output_begin(&leader, 512);     /* CPU0: 正在写 */
    perf_group_detach(&child);               /* CPU1: 释放 aux_buf */
    perf_aux_output_begin(&leader, 512);     /* CPU0: 写已释放的内存! */

    if (leader.aux_buf) { /* 可能已被 child 的 free 操作悬空 */
        free(leader.aux_buf);
    }
    return 0;
}
