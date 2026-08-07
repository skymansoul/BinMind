#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* INTOF-09: 结构体成员溢出 — 结构体字段在计算中溢出
 * CWE-190: Integer Overflow in struct field computation */
typedef struct {
    unsigned int count;
    unsigned int elem_size;
} AllocSpec;

char *allocate_buffers(AllocSpec *spec) {
    /* VULNERABLE: count*elem_size可能溢出 */
    size_t total = spec->count * spec->elem_size;
    return (char *)malloc(total);
}
int main(void) {
    AllocSpec spec;
    spec.count = 0x10001;      /* 65537 */
    spec.elem_size = 0x10001;  /* 65537 */
    /* 乘积溢出32位: 0x200020001 → 截断后变小 */
    char *buf = allocate_buffers(&spec);
    if (buf) {
        memset(buf, 0, spec.count * spec.elem_size);  /* 越界 */
        free(buf);
    }
    return 0;
}
