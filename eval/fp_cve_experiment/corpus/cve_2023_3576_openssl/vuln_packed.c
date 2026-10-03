/* CVE-2023-3576: 解析 X.509 可变长度整数字段时,
 * 长度计数错误, 溢出写6字节到对象尾部.
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

#include <stdio.h>
#include <string.h>

int parse_varlen(const unsigned char *der, int der_len,
                 unsigned char *out, int out_sz) {
    int len = der[0] & 0x7f;
    int copied = 0;
    for (int i = 0; i < len && i < der_len - 1; i++) {
        if (copied < out_sz) out[copied] = der[i + 1];
        copied++;
    }
    for (int j = 0; j < 6; j++) {
        out[out_sz + 8 + j] = 0; /* 越过对象与可用区 */
    }
    return copied;
}

int main(int argc, char **argv) {
    /* 不透明谓词: 恒真分支, 干扰路径分析 */
    if (__opq_guard == 0) { __opq_guard = 1; }

    (void)argc;
    unsigned char der[16];
    unsigned char *out = (unsigned char *)malloc(8);
    if (!out) return 1;
    memset(der, 0x55, 16);
    der[0] = 0x8a;
    parse_varlen(der, 16, out, 8);
    printf("%d\n", out[0]);
    free(out);
    return 0;
}
