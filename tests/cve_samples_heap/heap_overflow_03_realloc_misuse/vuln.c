/* realloc误用: realloc缩小后仍用原大小写入
 * 预期: 检测器应追踪realloc后的新大小
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *p = (char*)malloc(1024);
    p = (char*)realloc(p, 64);  /* 缩小到64 */
    memcpy(p, "overflow_data_more_than_64_bytes", 100);  /* 溢出 */
    free(p);
    return 0;
}
