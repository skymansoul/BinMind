/* CVE-2023-0286 (OpenSSL X.400 address) 堆溢出复现 — 类型混淆导致
   2 字节越界写. 简化: malloc(32) 后按地址长度 34 字节 memcpy. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *addr;
    char *payload;

    addr = (char *)malloc(32);
    payload = (char *)malloc(34);
    if (!addr || !payload) {
        return 1;
    }
    memset(payload, 'x', 34);
    memcpy(addr, payload, 34);
    free(addr);
    free(payload);
    return 0;
}
