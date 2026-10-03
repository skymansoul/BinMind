/*
 * CVE-2022-0185 — Linux kernel filesystem context 堆溢出 (简化复现)
 * Linux kernel 5.1-rc1 ~ 5.17-rc2, fsconfig() 系统调用中 legacy_parse_param() 的堆溢出.
 *
 * 漏洞机制:
 *   legacy_parse_param() 处理文件系统挂载参数时:
 *     1. 输入字符串长度 len = strlen(param->string) (用户可控)
 *     2. kmalloc(len + 2, GFP_KERNEL) 分配缓冲区
 *     3. memcpy(新buf, oldbuf, oldlen) + memcpy(新buf+oldlen, param->string, len)
 *     4. 但若 param->string 中包含非ASCII字符, 某个内部处理循环会过度复制,
 *        导致写入超过 len+2 字节.
 *
 * 具体触发: fsconfig(fd, FSCONFIG_SET_STRING, "\x00", key, 0):
 *   → legacy_parse_param 的输入 sanitization 绕过
 *   → 向内核堆块写越界
 *
 * 本文件简化: 模拟 legacy_parse_param() 中的 size calc 与 memcpy 不匹配问题.
 *
 * 影响: 容器逃逸 (非特权用户 → 内核任意代码执行).
 *      在 Kubernetes 等容器环境中特别危险.
 * 修复: kernel 5.17-rc3 — 修正 legacy_parse_param 选项大小计算.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * 漏洞函数: 模拟 legacy_parse_param() 的选项累积
 * 当新选项字符串包含特殊字符时, 内部魔术字符处理
 * 导致分配大小不足以容纳最终数据.
 */
char *legacy_parse_param_vuln(const char *existing, size_t exist_len,
                               const char *new_param, size_t param_len) {
    /*
     * 分配: 旧内容 + 新内容 + 分隔符 + null
     * 原始代码: kmalloc(exist_len + param_len + 2)
     */
    size_t total = exist_len + param_len + 2;
    char  *buf   = (char *)malloc(total);
    if (!buf) return NULL;

    /* 拷贝旧内容 */
    if (existing && exist_len > 0)
        memcpy(buf, existing, exist_len);

    /* 漏洞: 某些输入触发额外字符的写入
     * 原始代码中, 如果 param 的第一个字节是 ',' 或包含转义序列,
     * 会写入额外的分隔符, 但 total 计算未计入此额外字节.
     */
    size_t actual_extra = 0;
    if (new_param[0] == ',' || new_param[0] == '=') {
        /* 需要额外的转义字符, 但 total 未计入 */
        buf[exist_len] = '\\';       /* 写入转义符 */
        actual_extra = 1;
    }
    memcpy(buf + exist_len + actual_extra, new_param, param_len);

    size_t term_pos = exist_len + actual_extra + param_len;
    buf[term_pos] = '\0'; /* null 终止 — 可能越界! */

    size_t written = term_pos + 1;
    printf("  alloc=%zu, written=%zu (overflow=%zd)\n",
           total, written,
           (ssize_t)written - (ssize_t)total);
    return buf;
}

int main(void) {
    const char *exist   = "rw,noatime";
    size_t      elen    = strlen(exist);
    const char *evil    = ",exploit_option"; /* 以逗号开头的恶意参数 */
    size_t      plen    = strlen(evil);

    printf("[*] CVE-2022-0185 fsconfig heap overflow test\n");
    printf("  existing(%zu): \"%s\"\n", elen, exist);
    printf("  new param(%zu): \"%s\"\n", plen, evil);

    char *result = legacy_parse_param_vuln(exist, elen, evil, plen);
    if (result) {
        printf("[!] legacy_parse_param completed: \"%s\"\n", result);
        free(result);
    }
    return 0;
}
