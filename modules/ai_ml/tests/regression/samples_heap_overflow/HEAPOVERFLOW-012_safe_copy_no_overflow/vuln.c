#include <string.h>
#include <stdlib.h>
/* 负样本——memcpy大小<=malloc大小(经过对齐后)——检测器不应报告 */
void safe_copy_test(const char *data) {
    char *buf = malloc(64);
    if (!buf) return;
    memcpy(buf, data, 32); /* SAFE: 32 < usable(64)=64 */
    free(buf);
    buf = malloc(100);
    if (!buf) return;
    memcpy(buf, data, 100); /* SAFE: 100 <= usable(100)=112 */
    free(buf);
}
int main() {
    char data[128]; for(int i=0;i<128;i++) data[i]='Q';
    safe_copy_test(data);
    return 0;
}
