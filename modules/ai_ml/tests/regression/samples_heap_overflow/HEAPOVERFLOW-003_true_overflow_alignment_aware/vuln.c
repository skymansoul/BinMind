#include <string.h>
#include <stdlib.h>
/* 真正溢出——malloc(32)可用48, memcpy(64)→溢出16字节 */
void true_overflow_test(const char *data) {
    char *buf = malloc(32);
    if (!buf) return;
    memcpy(buf, data, 64); /* VULN: 64 > usable(32)=48 */
    free(buf);
}
int main() {
    char data[128]; for(int i=0;i<128;i++) data[i]='I';
    true_overflow_test(data);
    return 0;
}
