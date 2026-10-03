/* CVE-2016-2177: OpenSSL ECDH heap overflow */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ecdh_compute_key(size_t peer_key_len, const uint8_t *peer_key,
                      size_t expected_len) {
    /* BUG: alloc based on peer_key_len, but write based on expected_len */
    size_t alloc_sz = peer_key_len + 128;
    uint8_t *buf = (uint8_t *)malloc(alloc_sz);
    if (!buf) return;
    /* 若 expected_len > alloc_sz, 溢出 */
    memcpy(buf, peer_key, expected_len);
    free(buf);
}

int main(int argc, char **argv) {
    size_t pk = 256, ex = 1024;
    if (argc >= 3) { pk = (size_t)atol(argv[1]); ex = (size_t)atol(argv[2]); }
    uint8_t *key = (uint8_t *)malloc(ex);
    if (key) { memset(key, 0xEC, ex); ecdh_compute_key(pk, key, ex); free(key); }
    printf("done\n");
    return 0;
}
