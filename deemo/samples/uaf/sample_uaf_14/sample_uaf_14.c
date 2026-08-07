/*
 * sample_uaf_14 — Complex control flow: switch-case UAF.
 *
 * 多个case分支, 某些分支free, 某些不free.
 * switch后统一使用指针.
 *
 * TARPS预期: DEF_TP — 存在free到use的可达路径
 * 编译: gcc -o sample_uaf_14 sample_uaf_14.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    strcpy(buf, "switch_data");

    int mode = (argc > 1) ? atoi(argv[1]) : 1;

    switch (mode) {
        case 1:
            /* 保留buf, 不释放 */
            break;
        case 2:
            free(buf);
            /* buf未置NULL */
            break;
        case 3:
            /* 写入后释放 */
            strcpy(buf, "mode3");
            free(buf);
            break;
        default:
            free(buf);
            break;
    }

    /* UAF: mode=2/3/default时buf已free */
    printf("buf after switch: %s\n", buf);

    /* 只有mode=1时buf仍有效 */
    if (mode == 1) {
        free(buf);
    }

    return 0;
}
