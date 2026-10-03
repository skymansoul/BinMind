#include <string.h>
#include <stdlib.h>
/* 对齐边界测试——malloc(32)在glibc下实际可用48字节
 * 旧检测器: alloc=32, copy=40 → 误报为溢出
 * 新检测器: usable_size(32)=48, copy=40 → 安全(不应报告) */
void alignment_test(const char *data) {
    char *buf = malloc(32);
    if (!buf) return;
    memcpy(buf, data, 40); /* SAFE: 32→usable=48, 40<48 */
    free(buf);
}
int main() {
    char data[128]; for(int i=0;i<128;i++) data[i]='H';
    alignment_test(data);
    return 0;
}
