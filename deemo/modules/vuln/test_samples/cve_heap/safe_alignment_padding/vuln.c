/* safe_alignment_padding — 对齐 padding 内写入 (TN)。
 * malloc(17) 实际可用 24, 写入 20 合法。
 * Expected: TN */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(17);
    if (!buf) return 1;
    char src[24];
    memset(src, 'F', sizeof(src));
    memcpy(buf, src, 20);                 /* padding 区内 */
    free(buf);
    return 0;
}
