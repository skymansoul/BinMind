/* 多分配点: 两个malloc, 第二个溢出
 * 预期: 检测器正确关联p2和memcpy(p2)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *p1 = (char*)malloc(1024);  /* 安全 */
    char *p2 = (char*)malloc(32);    /* 将被溢出 */
    memcpy(p1, "safe_data", 9);      /* 安全 */
    memcpy(p2, "overflow_data_exceeding_32_bytes_limit", 100);  /* 溢出p2 */
    free(p1);
    free(p2);
    return 0;
}
