/*
 * CVE-2022-0185 — Linux kernel: fsconfig FUSE 堆溢出 (CWE-122→CWE-190)
 *
 * Linux kernel 5.15.18 之前: fs/fs_context.c 中 legacy_parse_param()
 * 对 FUSE 文件系统的参数长度处理不当. 攻击者通过
 * fsconfig(FSCONFIG_SET_STRING) 传入超过 PAGE_SIZE 的字符串,
 * 但分配使用 len+1, 后续使用 len+PAGE_SIZE 作为拷贝边界导致溢出.
 *
 * 文献: William Liu, "CVE-2022-0185: A Linux Kernel Bug", Jan 2022.
 * CVSS: 7.8 (High), CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define PAGE_SIZE 4096

int fs_param_parse(const char *param_str, size_t param_len) {
    /*
     * [VULN] param_len 攻击者可控, 可达 1024*1024
     * 但分配时少加了 PAGE_SIZE 偏移量
     */
    size_t alloc_sz = param_len + 1; /* 应该是 param_len + PAGE_SIZE + 1 */
    char *buf = (char *)malloc(alloc_sz);
    if (!buf) return -1;

    /* 第一步: 假设先拷贝一页的数据 */
    memcpy(buf, param_str, param_len > PAGE_SIZE ? PAGE_SIZE : param_len);

    /* [VULN] 第二段拷贝: 从偏移 PAGE_SIZE-1 开始,
     * 写入 param_len - PAGE_SIZE + 1 字节,
     * 但 buf 只有 param_len + 1 字节 (少分配了 ~PAGE_SIZE)
     */
    if (param_len > PAGE_SIZE) {
        size_t remaining = param_len - PAGE_SIZE + 1;
        /* buf 剩余空间: alloc_sz - PAGE_SIZE = (param_len+1) - PAGE_SIZE
         * 需写入空间: remaining = param_len - PAGE_SIZE + 1
         * 差额: +1 → off-by-one, 但在循环中累积为 off-by-N
         */
        memcpy(buf + PAGE_SIZE - 1,         /* dest = 4095 */
               param_str + PAGE_SIZE,        /* src = 4096 */
               remaining);                   /* [VULN] len = N - 4095 */
    }

    free(buf);
    return 0;
}

int main(void) {
    char *payload = (char *)malloc(PAGE_SIZE * 2);
    memset(payload, 'F', PAGE_SIZE * 2);

    /* 传入 2*PAGE_SIZE 的参数, 触发溢出 */
    int ret = fs_param_parse(payload, PAGE_SIZE * 2);
    free(payload);
    return ret;
}
