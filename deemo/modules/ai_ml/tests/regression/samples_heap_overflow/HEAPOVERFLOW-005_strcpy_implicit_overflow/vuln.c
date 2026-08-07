#include <string.h>
#include <stdlib.h>
/* strcpy隐式溢出——malloc(16)后strcpy(128字节字符串) */
void strcpy_heap_overflow(const char *input) {
    char *buf = malloc(16);
    if (!buf) return;
    strcpy(buf, input); /* VULN: input比16字节长→堆溢出 */
    free(buf);
}
int main() {
    char data[256]; for(int i=0;i<254;i++) data[i]='K'; data[254]=0;
    strcpy_heap_overflow(data);
    return 0;
}
