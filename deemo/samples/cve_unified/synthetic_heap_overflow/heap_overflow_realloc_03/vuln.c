/* heap_overflow_realloc_03 — realloc 缩小后仍写入旧大小
 * 误报诱因: realloc(ptr, new_size) 后 ptr 可能不变, 但有效大小已变.
 *   不追踪 realloc 语义的工具认为 ptr 还指向原来的大小.
 * 我们的优势: allocator_constraints.ReallocCheck 追踪 realloc 语义,
 *   若 new_size < old_size → 有效大小缩小 → 后续写入可能溢出.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    memset(buf, 'A', 256);
    /* realloc shrinks to 64; ptr may remain same */
    buf = (char *)realloc(buf, 64);
    if (!buf) return 1;
    /* still writes 256 bytes → overflows if realloc didn't move */
    memset(buf, 'B', 256);
    printf("%.64s\n", buf);
    free(buf);
    return 0;
}
