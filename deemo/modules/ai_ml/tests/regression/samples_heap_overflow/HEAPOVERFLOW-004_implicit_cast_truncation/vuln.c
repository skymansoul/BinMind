#include <string.h>
#include <stdlib.h>
#include <stdint.h>
/* 隐式类型截断——64位size_t被截断为32位int */
void truncation_test(const char *data, size_t len) {
    int alloc_len = (int)len; /* 截断! len=0x100000001 → alloc_len=1 */
    char *buf = malloc(alloc_len);
    if (!buf) return;
    memcpy(buf, data, len); /* VULN: len是原始的64位值，远大于alloc_len */
    free(buf);
}
int main() {
    char data[256]; for(int i=0;i<256;i++) data[i]='J';
    truncation_test(data, 256);
    return 0;
}
