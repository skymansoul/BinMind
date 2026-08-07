/*
 * sample_fmt_07 — argv[1] 作为格式字符串 (经典攻击向量)
 * 模式: argv[1] → printf(argv[1])
 * 期望: CONFIRMED (高置信度, 命令行可控)
 */
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 2)
        return 1;
    printf(argv[1]);  /* [VULN] 命令行参数作为格式字符串 */
    return 0;
}
