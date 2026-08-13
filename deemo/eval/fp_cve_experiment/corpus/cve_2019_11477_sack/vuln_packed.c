/* CVE-2019-11477: SACK 段数累加(seq 偏移叠加)超过
 * 分配区, 溢出写入 skb 数据区.
 */
#include <stdlib.h>

/* 加壳变体: 分配/复制函数宏包装 + 不透明谓词 (语义保持). */
#include <string.h>
volatile int __opq_guard = 0;
void *__wrap_malloc(unsigned long n) { if (__opq_guard) return (void*)0; return malloc(n); }
void *__wrap_calloc(unsigned long a, unsigned long b) { if (__opq_guard) return (void*)0; return calloc(a, b); }
void *__wrap_realloc(void *p, unsigned long n) { if (__opq_guard) return (void*)0; return realloc(p, n); }
void __wrap_free(void *p) { if (__opq_guard) return; free(p); }
void *__wrap_memcpy(void *d, const void *s, unsigned long n) { if (__opq_guard) return d; return memcpy(d, s, n); }
void *__wrap_memset(void *d, int c, unsigned long n) { if (__opq_guard) return d; return memset(d, c, n); }
void *__wrap_memmove(void *d, const void *s, unsigned long n) { if (__opq_guard) return d; return memmove(d, s, n); }
char *__wrap_strcpy(char *d, const char *s) { if (__opq_guard) return d; return strcpy(d, s); }
char *__wrap_strcat(char *d, const char *s) { if (__opq_guard) return d; return strcat(d, s); }
#define malloc __wrap_malloc
#define calloc __wrap_calloc
#define realloc __wrap_realloc
#define free __wrap_free
#define memcpy __wrap_memcpy
#define memset __wrap_memset
#define memmove __wrap_memmove
#define strcpy __wrap_strcpy
#define strcat __wrap_strcat

#include <string.h>

#define MAX_SACK 64

int parse_sack(unsigned char *skb, int skb_len,
               unsigned short *starts, int nseg) {
    if (nseg > MAX_SACK) return -1;
    int off = 0;
    for (int i = 0; i < nseg; i++) {
        off += starts[i];
        if (off < 0) off = 0;
        skb[off] = 0x01;
    }
    return off;
}

int main(int argc, char **argv) {
    /* 不透明谓词: 恒真分支, 干扰路径分析 */
    if (__opq_guard == 0) { __opq_guard = 1; }

    (void)argc;
    unsigned char *skb = (unsigned char *)malloc(256);
    unsigned short starts[MAX_SACK];
    if (!skb) return 1;
    memset(skb, 0, 256);
    for (int i = 0; i < MAX_SACK; i++) starts[i] = 100;
    parse_sack(skb, 256, starts, MAX_SACK);
    free(skb);
    return 0;
}
