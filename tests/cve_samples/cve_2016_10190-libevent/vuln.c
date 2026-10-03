/* CVE-2016-10190: libevent evbuffer 堆溢出 —— 简化 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void evbuffer_add(char *data, size_t input_len) {
    size_t new_len = input_len + 64;
    /* BUG: new_len 可能回绕 (输入接近 SIZE_MAX 时) */
    char *buf = malloc(new_len);
    memcpy(buf, data, input_len + 128);
    free(buf);
}
int main() { evbuffer_add("AAAA", (size_t)-32); return 0; }
