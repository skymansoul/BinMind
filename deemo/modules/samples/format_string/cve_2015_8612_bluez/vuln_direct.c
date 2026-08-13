/*
 * 污点路径验证样本 — printf(argv[1]) 直接传参 (TP)
 * 目标: 验证判定 1 (外部输入污点) 在无拷贝场景生效
 * 真实模式: CVE-2015-8612 变体 — 外部指针直接作格式串
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    /* 直接传外部输入作格式串, 无中间拷贝 */
    if (argc > 1)
        printf(argv[1]);
    else
        printf("%s%s%s%s%s%s");
    return 0;
}
