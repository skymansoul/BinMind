/* 误报测试: 多个alloc, 只有一个被写入但旧检测器全部标记
 * 预期: 指针身份追踪仅标记匹配的alloc-write对
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *a = (char*)malloc(32);   /* 小分配, 未被写入 */
    char *b = (char*)malloc(512);  /* 大分配, 安全写入 */
    char *c = (char*)malloc(64);   /* 中等分配, 未被写入 */
    /* 只写入b, a和c不应产生告警 */
    memcpy(b, "safe_large_write_to_b_only", 28);
    free(a); free(b); free(c);
    return 0;
}
