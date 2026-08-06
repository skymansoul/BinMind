/* CVE-2019-11477: Linux TCP SACK PANIC 堆溢出 —— 简化 */
#include <stdlib.h>
#include <string.h>
void rebuild_sack_blocks(unsigned int num_blocks, char *block_data) {
    unsigned int total = num_blocks * 8;
    /* BUG: num_blocks 来自网络, 大值导致 total 回绕为小值 */
    char *buf = malloc(total);
    memcpy(buf, block_data, num_blocks * 16);
    free(buf);
}
int main() { rebuild_sack_blocks(0x20000001, "AAAA"); return 0; }
