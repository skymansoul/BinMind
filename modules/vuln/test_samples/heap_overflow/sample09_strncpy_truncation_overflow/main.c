/* strncpy 截断溢出 — 截断后缺少 null 终止符造成后续越界.
 *
 * strncpy(exact_size) 不添加 null, strlen(buf)=未定义 → strcat 越界.
 * Expected: TP (strncpy truncation aware)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(16);
    if (!buf) return 1;
    /* strncpy(dst, src, 16): 填满16字节, 不加 '\0' */
    strncpy(buf, "AAAAAAAAAAAAAAAAAAAAAAAA", 16);
    /* strlen(buf) 可能 > 15 → strcat 越界写入 */
    strcat(buf, "BB");  /* OVERFLOW: 写入位置 > buf+15 */
    free(buf);
    return 0;
}
