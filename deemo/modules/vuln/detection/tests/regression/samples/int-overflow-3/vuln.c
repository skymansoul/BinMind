/* INT-3: 符号混淆——有符号→无符号转换
 * CWE-195, Ground Truth: -1→SIZE_MAX→巨大分配
 */
#include <stdlib.h>
#include <string.h>
void load(int count) {
    size_t sz = count * 128;  /* BUG: count=-1 → sz=SIZE_MAX-127 */
    char *buf = malloc(sz);
    memset(buf, 0, sz);  /* 尝试写SIZE_MAX字节→OOM或崩溃 */
    free(buf);
}
int main() { load(-1); return 0; }
