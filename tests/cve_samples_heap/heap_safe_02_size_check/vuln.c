/* 安全: 显式size检查后分配
 * 预期: 检测器识别if(size>ALLOC_MAX)守卫
 */
#include <stdlib.h>
#include <string.h>

void checked_alloc(int size, const char *data) {
    if (size <= 0 || size > 4096) return;  /* 边界检查 */
    char *buf = (char*)malloc(size);
    if (!buf) return;
    memcpy(buf, data, size);  /* 安全 */
    free(buf);
}

int main() {
    char d[1024];
    memset(d, 'K', 1024);
    checked_alloc(1024, d);
    return 0;
}
