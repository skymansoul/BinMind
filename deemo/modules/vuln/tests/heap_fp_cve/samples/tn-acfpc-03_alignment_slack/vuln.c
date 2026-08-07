/* TN 对照 3: 对齐裕量模式 — malloc(40) 实际 chunk 48 字节, 可写 40.
   写入恰 40 字节不越界. 以"请求大小"为边界的检测器报 FP;
   ACFPC 几何模型 usable=40 判定恰安全. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf;

    buf = (char *)malloc(40);
    if (!buf) {
        return 1;
    }
    memset(buf, 'a', 40);
    free(buf);
    return 0;
}
