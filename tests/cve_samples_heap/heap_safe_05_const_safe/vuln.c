/* 安全: 常量化写入, 明显小于分配
 * 预期: 常量判定: write(32) <= alloc(128) → SAFE
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *p = (char*)malloc(128);
    strcpy(p, "this is a short string");  /* < 128 */
    free(p);
    return 0;
}
