/* CVE-2019-1579: Palo Alto Networks GlobalProtect heap overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void parse_sslvpn_packet(uint32_t chunk_size, const uint8_t *chunk_data,
                         uint32_t total_size) {
    /* BUG: 分配 total_size, 但 chunk_size 可能 > total_size */
    uint8_t *buf = (uint8_t *)malloc(total_size + 16);
    if (!buf) return;
    memcpy(buf, chunk_data, chunk_size);  /* overflow if chunk_size > total_size+16 */
    free(buf);
}

int main(int argc, char **argv) {
    uint32_t cs = 4096, ts = 256;
    if (argc >= 3) { cs = (uint32_t)atoi(argv[1]); ts = (uint32_t)atoi(argv[2]); }
    uint8_t *data = (uint8_t *)malloc(cs);
    if (data) { memset(data, 'G', cs); parse_sslvpn_packet(cs, data, ts); free(data); }
    printf("done\n");
    return 0;
}
