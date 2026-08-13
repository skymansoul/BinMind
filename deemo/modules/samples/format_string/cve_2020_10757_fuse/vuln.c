/*
 * CVE-2020-10757 模式复刻 — FUSE 格式化字符串
 * 真实漏洞: 内核 FUSE 文件系统对用户可控路径/调试串直接
 *           格式化打印
 * 触发条件: 挂载点路径含 % 转换符
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: FUSE 挂载调试 */
void fuse_debug(const char *mount_path) {
    /* 缺陷: mount_path 用户可控 */
    printf(mount_path);
}

int main(int argc, char **argv) {
    char path[64];
    if (argc > 1) {
        strncpy(path, argv[1], sizeof(path) - 1);
        path[sizeof(path) - 1] = 0;
    } else {
        strcpy(path, "/mnt/%s%s%s%s%s");
    }
    fuse_debug(path);
    return 0;
}
