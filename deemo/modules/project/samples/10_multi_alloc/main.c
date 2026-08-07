/* 样本10: 多分配 — 仅一个溢出
 * 模式: 多个malloc, 其中一个溢出另一个. 检测器应定位到具体哪个溢出
 * 为何有效: 测试检测器的指针溯源精度 — 应能区分不同alloc返回的指针
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    /* 三个独立分配 */
    char *safe_buf  = (char *)malloc(256);
    char *vuln_buf   = (char *)malloc(64);   /* 只有64B */
    char *safe_buf2 = (char *)malloc(128);

    if (!safe_buf || !vuln_buf || !safe_buf2) return 1;

    /* 安全: 写入256B到256B分配的buffer */
    memset(safe_buf, 'S', 256);
    /* 溢出: 写入256B到64B分配的buffer */
    memset(vuln_buf, 'V', 256);
    /* 安全: 写入64B到128B分配的buffer */
    memset(safe_buf2, 'T', 64);

    printf("safe_buf=%p vuln_buf=%p safe_buf2=%p\n",
           (void *)safe_buf, (void *)vuln_buf, (void *)safe_buf2);

    free(safe_buf); free(vuln_buf); free(safe_buf2);
    return 0;
}
