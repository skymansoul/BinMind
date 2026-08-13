/* CVE-2015-0235 GHOST: __nss_hostname_digits_and_dots 中
 * 为 hostname 分配 strlen(host)+1 字节后用 strcpy 复制,
 * 当 host 为畸形长主机名时发生堆溢出.
 */
#include <stdlib.h>
#include <string.h>

char *lookup_host(const char *host) {
    size_t len = strlen(host) + 1;
    char *buf = (char *)malloc(len);
    if (!buf) return 0;
    memcpy(buf, host, len + 1);
    return buf;
}

int main(int argc, char **argv) {
    char host[1024];
    memset(host, 'A', 1023);
    host[1023] = 0;
    if (argc > 1) {
        memset(host, 'B', 800);
        host[800] = 0;
    }
    char *r = lookup_host(host);
    free(r);
    return 0;
}
