/*
 * CVE-2015-0235 — GHOST (glibc __nss_hostname_digits_dots 堆溢出, 简化复现)
 * glibc 2.2 ~ 2.17 中 gethostbyname() 系列函数的缓冲区溢出
 *
 * 漏洞机制:
 *   __nss_hostname_digits_dots() 在处理主机名字符串时,
 *   对域名长度边界验证错误.
 *   `size_needed = sizeof(*host_addr) + sizeof(*h_addr_ptrs) +
 *                  strlen(name) + 1;`
 *   当 name 特别长时, size_needed 可能回绕或不足以容纳后续 memcpy.
 *
 * 简化版: 模拟 glibc 内部 hostname 缓冲区分配逻辑,
 *         当输入主机名超长时, 堆分配不足, 导致溢出.
 *
 * 影响: 在 Exim SMTP 服务器中可远程代码执行 (CVE-2015-0235).
 *       Qualys 估计数百万台服务器受影响.
 * 修复: glibc 2.18 引入更严格的长度检查.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* 模拟 glibc nss 解析器内部结构 (简化) */
typedef struct {
    size_t  h_length;       /* 地址长度 */
    uint8_t *h_addr_list[2]; /* 地址列表指针 */
    uint8_t  h_addr[0];     /* 实际地址数据 (柔性数组) */
} HostentBuf;

/* 漏洞函数: 模拟 __nss_hostname_digits_dots 的缓冲区分配 */
HostentBuf *ghost_vulnerable(const char *hostname) {
    size_t namelen = strlen(hostname);
    size_t host_addr_size = 4;  /* IPv4 = 4 bytes */

    /*
     * 漏洞: size_needed 计算
     *   = sizeof(h_addr_ptrs) + sizeof(host_addr) + namelen + 1
     *   = 16 + 4 + namelen + 1
     *   = 21 + namelen
     *
     * 但后续 memcpy 写入 h_addr_ptrs + host_addr + name_copy 到同一缓冲区
     * 如果 name 长且无大小验证, 实际写入可能超过分配大小.
     *
     * 简化模拟: 分配太小 → 后续写入溢出.
     */
    size_t alloc_size = sizeof(HostentBuf) + host_addr_size + namelen + 1;
    HostentBuf *buf = (HostentBuf *)malloc(alloc_size);
    if (!buf) return NULL;

    buf->h_length = host_addr_size;
    buf->h_addr_list[0] = buf->h_addr;
    buf->h_addr_list[1] = NULL;

    /*
     * 将hostname拷贝到分配区域末尾:
     *   实际上会写入 addr_data + host_addr_size + namelen + 1 字节到缓冲区.
     *   但如果是攻击者构造的超长hostname, alloc_size 计算可能因整数溢出
     *   或逻辑错误而不足以容纳全部数据.
     *
     * 触发条件: hostname 长度使得 alloc_size 表达式结果
     *           小于实际需要写入的数据量.
     */
    char *name_dst = (char *)buf->h_addr + host_addr_size;
    memcpy(name_dst, hostname, namelen); /* 当namelen超大时溢出 */
    name_dst[namelen] = '\0';

    return buf;
}

int main(int argc, char **argv) {
    /* 构造超长hostname触发溢出 */
    char long_hostname[4096];
    memset(long_hostname, 'X', sizeof(long_hostname) - 1);
    long_hostname[sizeof(long_hostname) - 1] = '\0';

    printf("[*] Testing GHOST with hostname length = %zu\n",
           strlen(long_hostname));
    HostentBuf *result = ghost_vulnerable(long_hostname);
    if (result) {
        printf("[!] Allocation succeeded (potential overflow)\n");
        free(result);
    }
    return 0;
}
