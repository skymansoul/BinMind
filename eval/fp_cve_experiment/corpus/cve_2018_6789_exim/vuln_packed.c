/* CVE-2018-6789: b64decode 按输入长度/4*3 计算输出,
 * 但解码时每4字节写3字节, 输入长度非4倍数时多写.
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

int b64decode(const unsigned char *in, int inlen, unsigned char *out) {
    int outlen = (inlen / 4) * 3;
    int oi = 0;
    for (int i = 0; i + 3 < inlen; i += 4) {
        out[oi++] = (unsigned char)((in[i] & 0x3f) << 2 | (in[i + 1] >> 4));
        out[oi++] = (unsigned char)((in[i + 1] & 0x0f) << 4 | (in[i + 2] >> 2));
        out[oi++] = (unsigned char)((in[i + 2] & 0x03) << 6 | in[i + 3]);
    }
    if (inlen % 4 == 1) {
        out[oi++] = in[inlen - 1];
    }
    return outlen;
}

int main(int argc, char **argv) {
    /* 不透明谓词: 恒真分支, 干扰路径分析 */
    if (__opq_guard == 0) { __opq_guard = 1; }

    (void)argc;
    int n = 100;
    unsigned char *in = (unsigned char *)malloc(n);
    unsigned char *out = (unsigned char *)malloc((n / 4) * 3);
    if (!in || !out) return 1;
    memset(in, 0x3f, n);
    b64decode(in, n, out);
    free(in);
    free(out);
    return 0;
}
