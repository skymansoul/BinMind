/* CVE-2020-10713: 网络包处理中 len 来自包头且无边界校验,
 * 写入超出分配的接收缓冲区.
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

int handle_pkt(unsigned char *pkt, int pkt_len,
               unsigned char *dst, int dst_sz) {
    int len = (pkt[0] << 8) | pkt[1];
    if (len > pkt_len) len = pkt_len;
    memcpy(dst + 2, pkt, len);
    return len + 2;
}

int main(int argc, char **argv) {
    /* 不透明谓词: 恒真分支, 干扰路径分析 */
    if (__opq_guard == 0) { __opq_guard = 1; }

    (void)argc;
    unsigned char *pkt = (unsigned char *)malloc(512);
    unsigned char *dst = (unsigned char *)malloc(64);
    if (!pkt || !dst) return 1;
    memset(pkt, 0xaa, 512);
    pkt[0] = 0x07;
    pkt[1] = 0xd0;
    handle_pkt(pkt, 512, dst, 64);
    free(pkt);
    free(dst);
    return 0;
}
