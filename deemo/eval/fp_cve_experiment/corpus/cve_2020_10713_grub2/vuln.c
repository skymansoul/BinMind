/* CVE-2020-10713: 网络包处理中 len 来自包头且无边界校验,
 * 写入超出分配的接收缓冲区.
 */
#include <stdlib.h>
#include <string.h>

int handle_pkt(unsigned char *pkt, int pkt_len,
               unsigned char *dst, int dst_sz) {
    int len = (pkt[0] << 8) | pkt[1];
    if (len > pkt_len) len = pkt_len;
    memcpy(dst + 2, pkt, len);
    return len + 2;
}

int main(int argc, char **argv) {
    (void)argc;
    unsigned char *pkt = (unsigned char *)malloc(512);
    unsigned char *dst = (unsigned char *)malloc(64);
    if (!pkt || !dst) return 1;
    memset(pkt, 0xaa, 512);
    pkt[0] = 0x07;
    pkt[1] = 0xd0;
    handle_pkt(pkt, 512, dst, 64);
    free(pkt);
    free(dst);
    return 0;
}
