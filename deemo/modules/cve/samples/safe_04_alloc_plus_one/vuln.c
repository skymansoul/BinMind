/* N/A 安全对照: 分配与写入同源等大, 不可能溢出.
 * 预期: 检测器应判定 BENIGN (来源约束识别共享变量).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    size_t n = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc(n);
    if (!buf) return 1;
    memcpy(buf, argv[2], n);
    printf("buf[0]=%c\n", buf[0]);
    free(buf);
    return 0;
}
