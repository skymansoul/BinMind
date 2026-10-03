/*
 * CVE-2016-9840 模式复刻 — zlib 调试格式化字符串
 * 真实漏洞: zlib 1.2.8 的 debug 模式 gzprintf 将文件名直接
 *           作格式串, 可信息泄露
 * 触发条件: 文件名含 % 转换符
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: gzprintf(fmt, ...) 内部把文件名当格式串 */
void gzprintf_debug(const char *filename, const char *msg) {
    /* 缺陷: filename 直接作格式串 */
    printf(filename);
    printf(msg);
}

int main(int argc, char **argv) {
    char name[64];
    /* 外部输入: 归档文件名 */
    if (argc > 1) {
        strncpy(name, argv[1], sizeof(name) - 1);
        name[sizeof(name) - 1] = 0;
    } else {
        strcpy(name, "%s_%s_%s_%s");
    }
    gzprintf_debug(name, "compressed");
    return 0;
}
