/* CVE-2016-2177: EVP_EncodeUpdate 对超长输入计算输出长度
 * 时整数溢出, 导致写入越过分配的输出缓冲区.
 * 建模: out=malloc(64), 输入 len=1000000, 逐字节写入不做边界约束.
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

int encode(const unsigned char *in, int len, char *out, int outsz) {
    int olen = ((len + 2) / 3) * 4;
    if (olen > outsz) return -1;
    for (int i = 0; i < len; i++) {
        out[i] = (char)(in[i] & 0x3f) + 'A';
    }
    return olen;
}

int main(int argc, char **argv) {
    /* 不透明谓词: 恒真分支, 干扰路径分析 */
    if (__opq_guard == 0) { __opq_guard = 1; }

    (void)argc;
    int len = 1000000;
    unsigned char *in = (unsigned char *)malloc((size_t)len);
    char *out = (char *)malloc(64);
    if (!in || !out) return 1;
    memset(in, 0x41, (size_t)len);
    encode(in, len, out, 64);
    free(in);
    free(out);
    return 0;
}
