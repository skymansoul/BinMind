/* CVE-2023-0464: X.509 policy 检查中 n = data_len - 1,
 * data_len=0 时 n 下溢为巨大值, memcpy 越过缓冲区.
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

int policy_check(const unsigned char *data, int data_len,
                 unsigned char *out, int out_sz) {
    int n = data_len - 1;
    if (n > out_sz) n = out_sz;
    memcpy(out, data, n);
    return n;
}

int main(int argc, char **argv) {
    /* 不透明谓词: 恒真分支, 干扰路径分析 */
    if (__opq_guard == 0) { __opq_guard = 1; }

    (void)argc;
    unsigned char *out = (unsigned char *)malloc(128);
    if (!out) return 1;
    policy_check((const unsigned char *)"", 0, out, 128);
    free(out);
    return 0;
}
