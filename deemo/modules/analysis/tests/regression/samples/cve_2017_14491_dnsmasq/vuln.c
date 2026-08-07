/* CVE-2017-14491: dnsmasq DNSSEC heap overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void process_dnssec_rr(uint16_t rdlength, const uint8_t *rdata,
                       uint16_t declared_len) {
    /* BUG: 分配基于 rdlength, 但写入基于 declared_len */
    size_t alloc_sz = rdlength + 256;
    if (alloc_sz > 65536) alloc_sz = 65536;
    uint8_t *buf = (uint8_t *)malloc(alloc_sz);
    if (!buf) return;
    memcpy(buf, rdata, declared_len);  /* if declared_len > alloc_sz → overflow */
    free(buf);
}

int main(int argc, char **argv) {
    uint16_t rdl = 64, decl = 512;
    if (argc >= 3) { rdl = (uint16_t)atoi(argv[1]); decl = (uint16_t)atoi(argv[2]); }
    uint8_t *data = (uint8_t *)malloc(decl);
    if (data) { memset(data, 'D', decl); process_dnssec_rr(rdl, data, decl); free(data); }
    printf("done\n");
    return 0;
}
