/* CVE-2023-3576: 解析 X.509 可变长度整数字段时,
 * 长度计数错误, 溢出写6字节到对象尾部.
 */
#include <stdlib.h>
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
