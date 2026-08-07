/*
 * sample_uaf_06 — UAF with conditional free branch.
 *
 * free仅在特定条件分支执行, 但UAF在分支外.
 * 路径条件分析必须能识别: 若走未free的分支, use是安全的;
 * 若走了free分支, use是UAF.
 *
 * TARPS预期: DEF_TP — 存在一条从free到use的可达路径
 * 编译: gcc -o sample_uaf_06 sample_uaf_06.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    strcpy(buf, "initial");

    int flag = (argc > 1) ? 1 : 0;

    if (flag) {
        free(buf);
        /* buf未置NULL — 悬垂指针 */
    }

    /* UAF: 若flag=1, buf已释放但仍被使用 */
    strcpy(buf, "after conditional free");

    printf("buf=%s\n", buf);

    if (!flag) {
        free(buf);  /* 未free的分支 — cleanup */
    }
    return 0;
}
