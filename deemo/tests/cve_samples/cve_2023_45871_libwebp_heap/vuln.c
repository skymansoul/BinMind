/* CVE-2023-45871 — libwebp 堆溢出 (零日漏洞, 2023年野外利用)
 * BuildHuffmanTable 中错误的大小计算导致堆越界写入.
 * 类型: heap_buffer_overflow / CWE-122 / OOB write
 */
#include <stdlib.h>
#include <string.h>
void build_huffman_table(int table_size, char *input, int input_len) {
    int alloc_sz = table_size * sizeof(int);
    int *table = malloc(alloc_sz);
    /* BUG: 若 input_len > alloc_sz, 后续写入越界 */
    memcpy(table, input, input_len);
    free(table);
}
int main(void) {
    char payload[256]; memset(payload, 0xFF, 256);
    build_huffman_table(16, payload, 256);  /* 256 > 16*4=64 */
    return 0;
}
