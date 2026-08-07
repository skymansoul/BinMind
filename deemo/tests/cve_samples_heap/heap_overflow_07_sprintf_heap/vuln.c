/* sprintf堆溢出: 格式化字符串输出长度>缓冲区
 * 预期: 检测器识别sprintf的写入大小>分配
 */
#include <stdlib.h>
#include <stdio.h>

int main() {
    char *buf = (char*)malloc(32);
    sprintf(buf, "formatted string with value: %d and more text", 123456789);
    free(buf);
    return 0;
}
