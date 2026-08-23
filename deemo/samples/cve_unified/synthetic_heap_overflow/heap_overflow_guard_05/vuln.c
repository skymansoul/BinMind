/* heap_overflow_guard_05 — 有守卫的堆写入: 路径敏感分析的关键测试
 * 核心场景: if(size>1024) exit; buf=malloc(size); memcpy(buf, data, size);
 *   这里有守卫确保 size≤1024, 但静态分析看到 memcpy size=size 可能> malloc 参数.
 * 误报诱因: 不考虑守卫条件, 认为 size 可达任意值.
 * 我们的优势: path_condition_tracker 提取 if(size>1024) → size≤1024,
 *   精化 size interval → 若 1024 ≤ effective_chunk_size, 则 FILTER.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void process_input(size_t size, const char *data) {
    /* guard: sanitize size to prevent overflow */
    if (size > 1024) {
        fprintf(stderr, "size too large\n");
        return; /* exit path → size > 1024 unreachable for malloc */
    }
    /* at this point, size ≤ 1024 */
    char *buf = (char *)malloc(size);
    if (!buf) return;
    memcpy(buf, data, size); /* safe: size ≤ 1024 = malloc(size) */
    printf("%.1024s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    size_t sz = 2048; /* > 1024, triggers guard → early return */
    process_input(sz, "safe data");
    process_input(512, "short data"); /* safe */
    return 0;
}
