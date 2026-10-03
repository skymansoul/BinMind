/* CVE-2020-0022: Android Bluetooth heap overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct bt_packet { uint8_t type; uint16_t len; uint8_t payload[256]; };

void bt_process_l2cap(const struct bt_packet *pkt) {
    /* BUG: alloc_sz = pkt->len - 4 (removing header), but if len < 4 → underflow */
    size_t alloc_sz = (pkt->len > 4) ? (pkt->len - 4) : 256;
    uint8_t *buf = (uint8_t *)malloc(alloc_sz);
    if (!buf) return;
    /* 写入pkt->len字节, 可能超出alloc_sz */
    memcpy(buf, pkt->payload, pkt->len);
    free(buf);
}

int main(int argc, char **argv) {
    struct bt_packet pkt;
    pkt.type = 2;
    pkt.len = (argc >= 2) ? (uint16_t)atoi(argv[1]) : 512;
    memset(pkt.payload, 0xAA, 256);
    bt_process_l2cap(&pkt);
    printf("done\n");
    return 0;
}
