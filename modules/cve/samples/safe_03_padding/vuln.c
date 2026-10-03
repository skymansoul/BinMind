/* N/A 安全对照: 写入落在分配器 padding 区内.
 * malloc(62) glibc chunk 80字节, usable 72字节; 写入63字节安全.
 * 预期: 分配器语义模型判定 BENIGN.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(62);
    if (!buf) return 1;
    memcpy(buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAA", 63);
    printf("buf[0]=%c\n", buf[0]);
    free(buf);
    return 0;
}
