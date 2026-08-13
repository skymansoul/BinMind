/*
 * CVE-2022-26490 模式复刻 — NTFS 格式化字符串
 * 真实漏洞: 内核 NTFS 驱动对文件系统元数据字符串直接格式化
 * 触发条件: 恶意磁盘卷标含 % 转换符
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: NTFS 卷标调试 */
void ntfs_debug(const char *volume_label) {
    /* 缺陷: volume_label 来自磁盘镜像 */
    printf(volume_label);
}

int main(int argc, char **argv) {
    char label[32];
    if (argc > 1) {
        strncpy(label, argv[1], sizeof(label) - 1);
        label[sizeof(label) - 1] = 0;
    } else {
        strcpy(label, "%s%s%s%s");
    }
    ntfs_debug(label);
    return 0;
}
