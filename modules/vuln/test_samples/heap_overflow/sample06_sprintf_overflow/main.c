/* sprintf 堆溢出 — 无界写入到 malloc 缓冲区.
 *
 * malloc(32) 作为 sprintf 的目标, 输入超过32字节 → OVERFLOW.
 * Expected: TP (sprintf/inline copy detection)
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    /* sprintf: 无界写入, 输入 > 32 即溢出 */
    sprintf(buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  /* 44字节 */
                  "AAAAAAAAAAA");  /* 总计 55 > 32 → OVERFLOW */
    free(buf);
    return 0;
}
