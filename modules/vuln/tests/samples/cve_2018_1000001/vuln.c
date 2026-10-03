/* CVE-2018-1000001 — glibc realpath() 堆缓冲区欠分配 (off-by-one)
 *
 * 触发条件: getcwd() 返回的路径比预期多一个字符,
 * 但 malloc 分配的大小少一个字节, 导致 off-by-one 溢出。
 *
 * 测试目标: allocator model 应检测到 off-by-one 模式:
 * malloc(strlen(path)) → strcpy(buf, path)  缺少 +1 for '\0'
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void vulnerable_realpath(const char *user_path) {
    size_t len = strlen(user_path);
    /* BUG: 应为 len + 1, 缺少 null terminator 空间 */
    char *resolved = (char *)malloc(len);
    if (!resolved) return;

    strcpy(resolved, user_path);  /* overflow by 1 byte (null terminator) */
    printf("resolved: %s\n", resolved);
    free(resolved);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    vulnerable_realpath(argv[1]);
    return 0;
}
