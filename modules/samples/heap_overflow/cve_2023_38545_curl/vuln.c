/*
 * CVE-2023-38545 模式复刻 — curl SOCKS5 堆溢出
 * 真实漏洞: libcurl 在 HTTP 代理 + SOCKS5 场景, 主机名超过
 *           255 字节时 socks5 握手缓冲溢出 (CVE-2023-38545)
 * 触发条件: 主机名长度 > 255 (外部输入可控)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SOCKS5_MAX_HOST 255

struct socks5_req {
    char ver;
    char nmethods;
    char methods[4];
    char host_len;
    char host[SOCKS5_MAX_HOST];
};

char *build_socks5(const char *hostname) {
    size_t hlen = strlen(hostname);
    struct socks5_req *req =
        (struct socks5_req *)malloc(sizeof(struct socks5_req));
    if (!req) return NULL;
    req->ver = 5;
    req->nmethods = 1;
    req->methods[0] = 0;
    req->host_len = (char)hlen;     /* 缺陷: 截断但写不截断 */
    memcpy(req->host, hostname, hlen);  /* hlen > 255 越界 */
    return (char *)req;
}

int main(int argc, char **argv) {
    char host[512];
    memset(host, 'H', 300);         /* 300 > 255 */
    host[300] = 0;
    char *r = build_socks5(host);
    if (r) free(r);
    return 0;
}
