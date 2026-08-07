/*
 * CVE-2016-2173 模式复刻 — 堆溢出 via 大小计算错误
 * 真实漏洞: OpenSSL EVP_EncodeUpdate 过度分配后越界写
 * 触发条件: 输入长度 n 使 (n*4)/3 大于实际分配
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *encode(const unsigned char *in, size_t n) {
    /* 分配按 4/3 扩展, 但循环写入按 3 字节→4 字符推进 */
    size_t alloc = (n / 3 + 1) * 4 + 1;
    char *out = (char *)malloc(alloc);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i + 3 <= n) {
        out[j] = (char)(in[i] >> 2);
        out[j + 1] = (char)(((in[i] & 3) << 4) | (in[i + 1] >> 4));
        out[j + 2] = (char)(((in[i + 1] & 15) << 2) | (in[i + 2] >> 6));
        out[j + 3] = (char)(in[i + 2] & 63);
        i += 3;
        j += 4;
    }
    /* n % 3 != 0 时尾部写出 j+3 越界: 当 n=5, j=4, out[7] > alloc-1 */
    if (n % 3 == 1) { out[j] = 0; out[j + 1] = 0; out[j + 2] = 0; }
    if (n % 3 == 2) { out[j] = 0; out[j + 1] = 0; out[j + 2] = 0; out[j + 3] = 0; }
    return out;
}

int main(int argc, char **argv) {
    unsigned char data[8];
    memset(data, 0x41, sizeof(data));
    char *enc = encode(data, 5);   /* alloc=12, 但写出至 out[7..10] */
    if (enc) free(enc);
    return 0;
}
