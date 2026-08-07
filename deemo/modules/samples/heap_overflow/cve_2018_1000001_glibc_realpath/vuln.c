/*
 * CVE-2018-1000001 模式复刻 — realpath 越界写
 * 真实漏洞: glibc realpath() 在 getcwd 缓冲被文件系统攻击时
 *           发生堆越界写, 可提权 (Musl CVE-2018-11236 同族)
 * 触发条件: 路径解析结果长度超过分配的 PATH_MAX 缓冲
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH_BUF 32

char *resolve(const char *input) {
    char *buf = (char *)malloc(PATH_BUF);   /* 固定 32B 缓冲 */
    if (!buf) return NULL;
    size_t len = strlen(input);
    /* 缺陷: 未检查 len >= PATH_BUF 直接拷贝 */
    memcpy(buf, input, len + 1);            /* len 可达 255 */
    return buf;
}

int main(int argc, char **argv) {
    char path[256];
    memset(path, '/', sizeof(path));
    path[255] = 0;
    char *r = resolve(path);                /* 输入 255B > 32B 缓冲 */
    if (r) free(r);
    return 0;
}
