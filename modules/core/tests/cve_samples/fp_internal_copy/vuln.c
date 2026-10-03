/*
 * 误报样本-内部数据拷贝 — malloc(32) + memcpy(64): 写入的是内部常量, 非外部输入
 * 污点分析应识别为低风险 (非外部可控)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char INTERNAL_TEMPLATE[] =
    "This is a long internal template string used for formatting";

void format_output(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return;
    /*
     * 表面: alloc=32 < write=64 → 溢出
     * 实质: 源是内部常量, 攻击者无法控制溢出内容 → 可利用性低
     */
    memcpy(buf, INTERNAL_TEMPLATE, 64);
    printf("%.32s\n", buf);
    free(buf);
}

int main(void) {
    format_output();
    return 0;
}
