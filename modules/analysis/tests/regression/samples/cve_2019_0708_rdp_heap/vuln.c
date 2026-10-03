/* CVE-2019-0708: RDP heap overflow pattern */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct rdp_chunk { uint32_t size; uint8_t data[1024]; };

void process_rdp_chunk(const struct rdp_chunk *chunk) {
    size_t alloc_sz = (chunk->size & 0xFFFF) * 2;
    if (alloc_sz == 0) alloc_sz = 256;
    /* BUG: alloc_sz based on untrusted input, no overflow check */
    uint8_t *buf = (uint8_t *)malloc(alloc_sz);
    if (!buf) return;
    /* 写入大小也来自相同的字段, 但可能被位运算放大 */
    memcpy(buf, chunk->data, chunk->size);
    free(buf);
}

int main(int argc, char **argv) {
    struct rdp_chunk chunk;
    chunk.size = (argc >= 2) ? (uint32_t)atoi(argv[1]) : 2048;
    memset(chunk.data, 'B', sizeof(chunk.data));
    process_rdp_chunk(&chunk);
    printf("done\n");
    return 0;
}
