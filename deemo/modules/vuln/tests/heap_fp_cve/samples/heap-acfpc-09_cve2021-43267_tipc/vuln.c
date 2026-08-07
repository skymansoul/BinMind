/* CVE-2021-43267 (Linux TIPC) 堆溢出复现 — tipc_nl_retrieve_key 对
   未初始化的 key 域执行无边界 memcpy, 源长度超过分配. 简化:
   malloc(16) + memcpy(buf, src, 64). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *key;
    char *src;

    key = (char *)malloc(16);
    src = (char *)malloc(64);
    if (!key || !src) {
        return 1;
    }
    memset(src, 'k', 64);
    memcpy(key, src, 64);
    free(key);
    free(src);
    return 0;
}
