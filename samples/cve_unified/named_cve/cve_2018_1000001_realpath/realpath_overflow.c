/*
 * CVE-2018-1000001 — glibc realpath() 堆溢出 (简化复现)
 * glibc < 2.27, realpath() 函数在处理包含特殊挂载点的路径时的堆溢出.
 *
 * 漏洞机制:
 *   realpath() 在处理符号链接时, 如果路径解析过程中
 *   遇到 NAME_MAX 长度的目录名, 内部缓冲区大小计算错误.
 *   分配的大小基于路径前缀长度, 但实际写入包含全路径+null终止符,
 *   导致 off-by-one 或更大的溢出.
 *
 * 影响: 本地提权 (任何使用 realpath() 的SUID程序).
 * 修复: glibc 2.27 — 修正缓冲区分配逻辑.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

/*
 * 漏洞函数: 模拟 realpath 的路径解析缓冲区分配
 * 原始代码中, getcwd() 和符号链接解析的缓冲区复用逻辑有缺陷
 */
char *realpath_vulnerable(const char *path) {
    size_t path_len  = strlen(path);
    /*
     * 漏洞: 分配 PATH_MAX, 但在某些代码路径中
     *       (符号链接展开后的路径拼接)
     *       实际写入的数据可能超过 PATH_MAX.
     *
     * 原始漏洞关键: 在 __realpath 中, 如果路径包含
     *   /proc/self/fd/N 等特殊挂载点, resolved_name 缓冲区
     *   的边界检查不充分. 简化模拟:
     */
    size_t alloc  = path_len + 256; /* 模拟 PATH_MAX=4096, 但实际写入更多 */
    char  *resolved = (char *)malloc(alloc);
    if (!resolved) return NULL;

    /*
     * 模拟符号链接展开: 原始路径 "a/b/c" 中的某组件
     * 可能是挂载点, 展开后长度远超 path_len + NAME_MAX.
     * 合并后的路径可能超出 alloc.
     */
    size_t resolved_len = 0;
    const char *components[] = {"/mnt", "/very_long_mountpoint_name_that_exceeds_buffer",
                                 "/subdir", "/target", NULL};
    for (int i = 0; components[i]; i++) {
        size_t clen = strlen(components[i]);
        if (resolved_len + clen + 1 > alloc) {
            printf("  [!] Component '%s' would overflow: %zu + %zu > %zu\n",
                   components[i], resolved_len, clen, alloc);
            /* 但原始代码未做此检查, 继续写入 */
        }
        memcpy(resolved + resolved_len, components[i], clen);
        resolved_len += clen;
        if (components[i+1] != NULL) {
            resolved[resolved_len++] = '/';
        }
    }
    resolved[resolved_len] = '\0';
    printf("  alloc=%zu, resolved_len=%zu\n", alloc, resolved_len);
    return resolved;
}

int main(void) {
    printf("[*] glibc realpath overflow test (CVE-2018-1000001)\n");
    char *result = realpath_vulnerable("/proc/self/fd/0");
    if (result) {
        printf("[!] realpath: %s\n", result);
        free(result);
    }
    return 0;
}
