/* 用户输入控制分配大小的堆溢出
 * alloc=user_val(256), write=实际数据(2048)
 * 预期: 检测器追踪符号变量n, 识别write(n?) vs alloc(n)
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void process_input(int n, const char *data, int data_len) {
    char *buf = (char*)malloc(n);
    /* 漏洞: data_len未与n比较 */
    memcpy(buf, data, data_len);
    free(buf);
}

int main() {
    char data[2048];
    memset(data, 'B', 2048);
    process_input(256, data, 2048);
    return 0;
}
