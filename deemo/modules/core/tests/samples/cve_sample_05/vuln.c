/* CVE-2016-10190 — FFmpeg http.c 堆溢出 (接收缓冲区大小计算错误) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *receive_chunk(int fd, size_t *out_len) {
    size_t chunk_hdr = 1024; /* 从网络读到的块大小 */
    char *buf = (char *)malloc(chunk_hdr);
    if (!buf) return NULL;
    /* 漏洞: 实际接收量超过 chunk_hdr */
    memset(buf, 0, chunk_hdr + 512); /* 多写了 512B */
    *out_len = chunk_hdr + 512;
    return buf;
}

int main(void) {
    size_t len;
    char *data = receive_chunk(0, &len);
    printf("received %zu bytes\n", len);
    free(data);
    return 0;
}
