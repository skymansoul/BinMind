#include <string.h>
#include <stdlib.h>
/* 多分配场景——测试L1约束配对能否正确匹配malloc和memcpy */
void multi_alloc_test(const char *data, int len) {
    char *safe_buf = malloc(256);
    char *vuln_buf = malloc(32);
    char *safe_buf2 = malloc(512);
    if (!safe_buf || !vuln_buf || !safe_buf2) return;
    memcpy(safe_buf, data, 256);   /* safe: 256 <= 256 */
    memcpy(vuln_buf, data, len);   /* VULN: len可达256, 但只有32 */
    memcpy(safe_buf2, data, 512);  /* safe: 512 <= 512 */
    free(safe_buf); free(vuln_buf); free(safe_buf2);
}
int main() {
    char data[512]; for(int i=0;i<512;i++) data[i]='G';
    multi_alloc_test(data, 256);
    return 0;
}
