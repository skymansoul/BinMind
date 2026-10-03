/*
 * CVE-2015-0235 — GHOST: glibc gethostbyname 堆溢出 (CWE-122)
 *
 * glibc 2.2 ~ 2.17: __nss_hostname_digits_dots() 中的 heap buffer overflow.
 * gethostbyname_r 在解析特定格式的主机名时, 在堆分配的缓冲区中越界写入.
 *
 * 根因: realloc 后的大小计算错误 — 当 strlen 计算与 realloc 参数不一致时,
 * 函数可能写入超出新分配的大小的数据.
 *
 * 文献: Qualys Security Advisory CVE-2015-0235, Jan 2015.
 * CVSS: 7.6 (Critical), CVSS:2.0/AV:N/AC:H/Au:N/C:C/I:C/A:C
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAXDNAME 1025

/* 模拟 __nss_hostname_digits_dots 的漏洞逻辑 */
static char *resolve_hostname(const char *name, size_t namelen) {
    size_t buf_size = MAXDNAME;
    char *buffer = (char *)malloc(buf_size);
    if (!buffer) return NULL;

    /* 第一次 realloc — 可能缩小 buffer */
    size_t needed = namelen + 8; /* 8 = sizeof(host_data) overhead */

    /* [VULN] realloc 返回的指针可能小于原始 buf_size,
     * 但后续代码仍用旧 buf_size 作为写入上限
     */
    char *new_buf = (char *)realloc(buffer, needed);
    if (!new_buf) {
        free(buffer);
        return NULL;
    }

    /* [VULN] 使用旧的 buf_size (MAXDNAME) 而非新的 needed 大小
     * 当 needed < buf_size 时虽然安全, 但当 namelen 增大到接近 MAXDNAME
     * 且后续操作使用 new_buf + 固定偏移写入时, 可能溢出 needed 的新边界
     */
    size_t write_sz = namelen;
    if (write_sz > buf_size) /* 使用旧的大小检查 ← 缺陷! */
        write_sz = buf_size;

    memcpy(new_buf, name, write_sz); /* 可能写入超过 needed 的量 */
    new_buf[write_sz] = '\0';

    return new_buf;
}

int main(void) {
    char hostname[1100];
    memset(hostname, 'A', 1090);
    hostname[1090] = '\0';

    char *result = resolve_hostname(hostname, 1090);
    if (result) {
        printf("resolved: %s\n", result);
        free(result);
    }
    return 0;
}
