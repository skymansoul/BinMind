/* 运行时堆边界插桩 shim — malloc/memcpy 包裹, 记录越界复制.
 *
 * 创建: 2026-08-11
 * 用途: 作为 qemu_tracer.py 的 asan 回退 ground truth.
 *       原理: 宏替换样本中的 malloc/free/memcpy/memset/strcpy,
 *       记录分配大小表, 复制前校验目标是否越界.
 * 注意: 仅在样本为自包含C时有效; 使用 -include 注入, 不修改样本源码.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define SHIM_MAX_OBJ 8192

static struct { void *p; size_t n; } shim_objs[SHIM_MAX_OBJ];
static int shim_nobj = 0;
static int shim_overflows = 0;

static void shim_track(void *p, size_t n) {
    if (p && shim_nobj < SHIM_MAX_OBJ) {
        shim_objs[shim_nobj].p = p;
        shim_objs[shim_nobj].n = n;
        shim_nobj++;
    }
}

static size_t shim_size_of(void *p) {
    for (int i = 0; i < shim_nobj; i++) {
        if (shim_objs[i].p == p) return shim_objs[i].n;
    }
    return 0;
}

static void shim_check_write(void *dst, size_t len) {
    /* 选择最接近 dst 的已跟踪对象 (base ≤ dst), 避免错配相邻对象 */
    int best = -1;
    size_t best_off = (size_t)-1;
    for (int i = 0; i < shim_nobj; i++) {
        char *base = (char *)shim_objs[i].p;
        if (!base) continue;
        if (dst >= (void *)base) {
            size_t off = (size_t)((char *)dst - base);
            if (off < best_off) {
                best_off = off;
                best = i;
            }
        }
    }
    if (best >= 0) {
        char *base = (char *)shim_objs[best].p;
        size_t n = shim_objs[best].n;
        if (best_off + len > n) {
            fprintf(stderr, "SHIM-OVERFLOW base=%p size=%zu off=%zu "
                    "copy=%zu\n", base, n, best_off, len);
            fflush(stderr);
            shim_overflows++;
        }
    }
}

static void shim_report(void) __attribute__((destructor));
static void shim_report(void) {
    fprintf(stderr, "SHIM-TOTAL-OVERFLOWS %d\n", shim_overflows);
    fflush(stderr);
}

#undef malloc
void *shim_malloc(size_t n) {
    void *p = malloc(n);
    shim_track(p, n);
    return p;
}
#define malloc shim_malloc

#undef calloc
void *shim_calloc(size_t a, size_t b) {
    void *p = calloc(a, b);
    shim_track(p, a * b);
    return p;
}
#define calloc shim_calloc

#undef realloc
void *shim_realloc(void *p, size_t n) {
    void *q = realloc(p, n);
    if (q) shim_track(q, n);
    return q;
}
#define realloc shim_realloc

#undef free
void shim_free(void *p) {
    free(p);
}
#define free shim_free

#undef memcpy
void *shim_memcpy(void *d, const void *s, size_t n) {
    shim_check_write(d, n);
    return memcpy(d, s, n);
}
#define memcpy shim_memcpy

#undef memmove
void *shim_memmove(void *d, const void *s, size_t n) {
    shim_check_write(d, n);
    return memmove(d, s, n);
}
#define memmove shim_memmove

#undef memset
void *shim_memset(void *d, int c, size_t n) {
    shim_check_write(d, n);
    return memset(d, c, n);
}
#define memset shim_memset

#undef strcpy
char *shim_strcpy(char *d, const char *s) {
    size_t n = strlen(s) + 1;
    shim_check_write(d, n);
    return strcpy(d, s);
}
#define strcpy shim_strcpy

#undef strcat
char *shim_strcat(char *d, const char *s) {
    size_t n = strlen(s) + 1;
    shim_check_write(d, n);
    return strcat(d, s);
}
#define strcat shim_strcat
