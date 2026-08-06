/* CVE-2022-0185: Linux fscontext 堆溢出 —— 简化 */
#include <stdlib.h>
#include <string.h>
void fscontext_parse_legacy(char *data, unsigned int data_len) {
    unsigned int capped = (data_len < 4096) ? data_len : 4096;
    char *buf = malloc(capped);
    /* BUG: data_len 被截断但后续使用原始 data_len, 若 data_len>4096 则溢出 */
    memcpy(buf, data, data_len);
    free(buf);
}
int main() { fscontext_parse_legacy("AAAA", 8192); return 0; }
