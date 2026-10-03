/* CVE-2022-20000 (堆溢出) — 拷贝后追加导致越界
 * 漏洞类型: 堆溢出 (strcat追加无边界)
 * 触发条件: malloc(64), strcpy(buf, a), strcat(buf, b) 累积溢出
 * 根因: strcat不检查目标剩余空间
 * 有效原因: 测试BWR对无界写入的恢复判定 (固定缓冲+无界追加)
 */
#include <stdlib.h>
#include <string.h>

void append_strings(char *a, char *b) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    strcpy(buf, a);        /* a足够短 */
    strcat(buf, b);        /* b过长 → 溢出 */
    free(buf);
}

int main() {
    char big[128];
    memset(big, 'B', 100);
    big[100] = 0;
    append_strings("start", big);
    return 0;
}
