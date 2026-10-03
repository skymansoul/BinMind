#include <string.h>
#include <stdlib.h>

__attribute__((noinline)) void copy_string(const char *src) {
    char *dst = malloc(64);
    if (!dst) return;
    strcpy(dst, src);   /* VULN: src可>63字节 */
    volatile char probe = dst[0];   /* 观察堆写, 防DCE */
    (void)probe;
    free(dst);
}

int main(void) {
    char long_str[1024];
    memset(long_str, 'D', sizeof(long_str) - 1);
    long_str[1023] = 0;
    copy_string(long_str);
    return 0;
}
