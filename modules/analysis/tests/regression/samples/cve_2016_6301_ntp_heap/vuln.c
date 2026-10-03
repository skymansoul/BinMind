/* CVE-2016-6301: NTP CRYPTO_NAK heap overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void process_ntp_packet(const uint8_t *pkt, uint16_t pkt_len) {
    size_t alloc_sz = pkt_len * 4;
    if (alloc_sz < 128) alloc_sz = 128;
    uint8_t *buf = (uint8_t *)malloc(alloc_sz);
    if (!buf) return;
    /* BUG: pkt_len * 4 may overflow uint16_t, and the resulting alloc_sz
     * may be smaller than what's actually copied */
    memcpy(buf, pkt, pkt_len * 3);  /* 3x vs 4x mismatch */
    free(buf);
}

int main(int argc, char **argv) {
    uint16_t len = (argc >= 2) ? (uint16_t)atoi(argv[1]) : 100;
    uint8_t pkt[512]; memset(pkt, 'N', 512);
    process_ntp_packet(pkt, len);
    printf("done\n");
    return 0;
}
