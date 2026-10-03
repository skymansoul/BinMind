/*
 * CVE-2018-11529 模式复刻 — VLC 格式化字符串
 * 真实漏洞: VLC 媒体播放器 demux 模块对文件内嵌元数据直接
 *           格式化打印, 恶意媒体可触发
 * 触发条件: 元数据字符串含 % 转换符
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 复刻: 媒体元数据 (艺术家/标题) 直接作格式串 */
void print_metadata(const char *artist, const char *title) {
    /* 缺陷: 均来自媒体文件, 用户可控 */
    printf(artist);
    printf(title);
}

int main(int argc, char **argv) {
    char artist[64], title[64];
    if (argc > 2) {
        strncpy(artist, argv[1], sizeof(artist) - 1);
        artist[sizeof(artist) - 1] = 0;
        strncpy(title, argv[2], sizeof(title) - 1);
        title[sizeof(title) - 1] = 0;
    } else {
        strcpy(artist, "%s%s%s%s%s");
        strcpy(title, "%x%x%x%x%x%x");
    }
    print_metadata(artist, title);
    return 0;
}
