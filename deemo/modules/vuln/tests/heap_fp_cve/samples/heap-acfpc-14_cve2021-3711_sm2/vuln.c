/* CVE-2021-3711 (OpenSSL SM2 解密) 堆溢出复现 — 解密输出长度被错误
   计算, 明文缓冲不足. 简化: malloc(64) + memcpy(buf, cipher, 96). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *plain;
    char *cipher;

    plain = (char *)malloc(64);
    cipher = (char *)malloc(96);
    if (!plain || !cipher) {
        return 1;
    }
    memset(cipher, 'c', 96);
    memcpy(plain, cipher, 96);
    free(plain);
    free(cipher);
    return 0;
}
