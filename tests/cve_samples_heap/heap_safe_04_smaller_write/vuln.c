/* 安全: 写入量小于分配量
 * 预期: 检测器应过滤 (write_size < alloc_size)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *p = (char*)malloc(256);
    memcpy(p, "small_write", 11);  /* 安全: 11 < 256 */
    free(p);
    return 0;
}
