/* sample17_false_positive_test: malloc对齐padding访问 — 应被过滤
 * Ground Truth: SAFE — 访问malloc返回指针附近的偏移属于对齐padding
 * Pattern: ptmalloc2 将malloc(1)对齐到至少16B, 写访问前16B是安全的
 */
#include <stdlib.h>
#include <string.h>
int main() {
    char *p = malloc(100);
    /* 写100B到分配的前100B → 完全安全, 未溢出 */
    memset(p, 0, 100);
    free(p);
    return 0;
}
