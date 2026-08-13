/* UAF-08: CVE-2020-14386 (AF_PACKET) 简化复刻
 * CVE: CVE-2020-14386, 内核 AF_PACKET 套接字堆 UAF.
 * 触发: 条件分支内 free(obj); 分支结束后无条件使用 obj → UAF.
 * 为何有效: 释放发生在条件路径, 使用位于汇合点, 静态检测需
 *       跨分支判定释放-使用序; 对象未置空.
 */
#include <stdio.h>
#include <stdlib.h>

void conditional_free_use(int flag) {
    char *obj = (char *)malloc(64);
    if (!obj) {
        return;
    }
    if (flag) {
        free(obj);
    }
    obj[0] = 'A';   /* UAF: flag=1 时 obj 悬垂 */
}

int main(void) {
    conditional_free_use(1);
    return 0;
}
