/*
 * CVE-16: 真实世界堆溢出模式 — HTTP头解析模拟
 *
 * 模式: 解析 Content-Length → 分配 buf → 读入数据但未正确检查边界
 * 借鉴: CVE-2015-7547 (glibc getaddrinfo 堆溢出)
 *        CVE-2022-3602 (OpenSSL 3.x 堆溢出)
 *
 * 触发: content_length=256 → malloc(256), 实际接收 320B → 溢出 64B
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct http_request {
    int content_length;
    char *body;
};

void parse_body(struct http_request *req, const char *input, int input_len) {
    // 分配 Content-Length 指定的大小
    req->body = (char *)malloc(req->content_length);
    if (!req->body) return;

    // BUG: 使用 input_len 而非 req->content_length
    // 如果 input_len > content_length → 溢出
    memcpy(req->body, input, input_len);
}

int main(void) {
    struct http_request req;
    req.content_length = 256;

    // 模拟接收了超过 Content-Length 的数据
    char fake_input[320];
    memset(fake_input, 'E', 320);

    parse_body(&req, fake_input, 320);

    printf("real-world pattern: alloc=%d write=%d\n",
           req.content_length, 320);
    free(req.body);
    return 0;
}
