/*
 * CVE-2024-2961 模式复刻 — iconv ISO-2022-CN-EXT 堆越界写
 * 真实漏洞: glibc iconv 在 ISO-2022-CN-EXT 转换中含无效序列
 *           时越界写 4 字节, 经 PHP/git 等可 RCE
 * 触发条件: 转换缓冲尾部含无效多字节序列
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OUT_MAX 16

/* 复刻 iconv 转换: 输入无效序列时向输出缓冲写 4 字节
   但未检查输出剩余空间 */
size_t my_iconv(const char *in, size_t inlen, char *out, size_t outlen) {
    size_t o = 0, i = 0;
    while (i < inlen) {
        if ((unsigned char)in[i] == 0x1B) {   /* ESC 转义序列 */
            if (o + 4 > outlen) return (size_t)-1;  /* 有检查 */
            out[o++] = 0x1B; out[o++] = '$';
            out[o++] = ')'; out[o++] = 'A';   /* 4 字节写出 */
            i += 3;
        } else {
            if (o + 2 > outlen) return (size_t)-1;
            out[o++] = in[i]; out[o++] = in[i];  /* 双字节写出 */
            i += 1;
        }
    }
    return o;
}

char *convert(const char *in, size_t inlen) {
    char *out = (char *)malloc(OUT_MAX);
    if (!out) return NULL;
    size_t n = my_iconv(in, inlen, out, OUT_MAX);
    if (n == (size_t)-1) { free(out); return NULL; }
    return out;
}

int main(int argc, char **argv) {
    /* 构造: 12 个普通字节 → 24 字节输出 > 16 缓冲 */
    char in[16];
    memset(in, 'X', 12);
    in[12] = 0;
    char *r = convert(in, 12);
    if (r) free(r);
    return 0;
}
