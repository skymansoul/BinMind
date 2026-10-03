/* 循环中的堆溢出: alloc < loop_write
 * 预期: 检测器识别循环写入量>分配量
 */
#include <stdlib.h>
#include <string.h>

void process(int n) {
    char *buf = (char*)malloc(32);
    /* 漏洞: n可达256, 但alloc仅32 */
    for (int i = 0; i < n; i++) {
        buf[i] = (char)i;
    }
    free(buf);
}

int main() {
    process(256);
    return 0;
}
