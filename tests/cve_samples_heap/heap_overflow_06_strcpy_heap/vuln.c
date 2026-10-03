/* strcpy堆溢出: alloc不足容纳源字符串
 * 预期: 检测器识别strcpy/strncpy作为写入函数
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *p = (char*)malloc(16);
    strcpy(p, "this_string_is_much_longer_than_16_bytes");
    free(p);
    return 0;
}
