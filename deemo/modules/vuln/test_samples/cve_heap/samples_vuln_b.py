# coding: utf-8
# 创建: 2026-07-19  |  语料数据 B——TP 样本 7-12
#
"""TP 样本数据 (cve_2021_3156 ~ cve_2024_2961). 仅数据, 无逻辑."""

SAMPLES_VULN_B = [
    {
        "id": "cve_2021_3156_sudo",
        "cve": "CVE-2021-3156",
        "title": "sudo Baron Samedit heap overflow (unbounded copy)",
        "pattern": "malloc(user_len) 后 strcpy 无界",
        "trigger": "argv 末尾项 strcpy 无长度限制",
        "why": "strcpy 无界 → R0 直接溢出",
        "code": r'''/* CVE-2021-3156 — sudo Baron Samedit 堆溢出 (strcpy 无界)。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    size_t n = 128;
    if (argc > 1) n = strlen(argv[1]);
    char *buf = (char *)malloc(n);
    if (!buf) return 1;
    strcpy(buf, argv[1]);                 /* 无界 → 越界 */
    free(buf);
    return 0;
}
''',
    },
    {
        "id": "cve_2022_0185_kernel",
        "cve": "CVE-2022-0185",
        "title": "Linux kernel fs_context heap overflow (length mismatch)",
        "pattern": "malloc(len) 后 memcpy(user_len) 跨函数",
        "trigger": "user_len 大于 len 时越界",
        "why": "写入长度来自外部, 与分配长度不同源",
        "code": r'''/* CVE-2022-0185 — kernel fs_context 堆溢出 (长度错配)。
 * 分配 64, 写入 argv 长度 (可超 64)。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    size_t user_len = strlen(argv[argc - 1]);
    memcpy(buf, argv[1], user_len);       /* 外部长度写入 */
    free(buf);
    return 0;
}
''',
    },
    {
        "id": "cve_2022_3602_openssl",
        "cve": "CVE-2022-3602",
        "title": "OpenSSL punycode heap overflow (off-by-one)",
        "pattern": "malloc(88) 后 memcpy(89)",
        "trigger": "写入 89 恰超分配 88 可用空间",
        "why": "off-by-one: 89 > usable(88)=88",
        "code": r'''/* CVE-2022-3602 — OpenSSL punycode 堆 off-by-one。
 * malloc(88) + memcpy(89)。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(88);
    if (!buf) return 1;
    char src[96];
    memset(src, 'D', sizeof(src));
    memcpy(buf, src, 89);                 /* off-by-one 越界 */
    free(buf);
    return 0;
}
''',
    },
    {
        "id": "cve_2023_2513_bpf",
        "cve": "CVE-2023-2513",
        "title": "kernel bpf (user namespaces) heap write overflow",
        "pattern": "malloc(48) 后 memset(96)",
        "trigger": "固定写入 96 > 分配 48 的可用空间",
        "why": "固定常量越界 (R4 可证明)",
        "code": r'''/* CVE-2023-2513 — kernel bpf 堆写越界。
 * malloc(48) + memset(96)。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(48);
    if (!buf) return 1;
    memset(buf, 0x42, 96);                /* 越界 48B */
    free(buf);
    return 0;
}
''',
    },
    {
        "id": "cve_2023_38545_curl",
        "cve": "CVE-2023-38545",
        "title": "curl SOCKS5 proxy heap overflow",
        "pattern": "malloc(len) 后 memcpy(len+32) 动态",
        "trigger": "hostname 过长时 len+32 越界",
        "why": "写入量含常数差, 分配量受外部影响",
        "code": r'''/* CVE-2023-38545 — curl SOCKS5 堆溢出。
 * 分配 len, 写入 len+32。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    size_t len = 128;
    if (argc > 1) len = strlen(argv[1]);
    char *buf = (char *)malloc(len);
    if (!buf) return 1;
    memcpy(buf, argv[1], len + 32);       /* 恒越界 */
    free(buf);
    return 0;
}
''',
    },
    {
        "id": "cve_2024_2961_glibc",
        "cve": "CVE-2024-2961",
        "title": "glibc iconv heap overflow (write past allocation)",
        "pattern": "malloc(128) 后 memcpy(160)",
        "trigger": "固定写入 160 > 分配 128 的可用空间",
        "why": "固定常量越界 (R4 可证明)",
        "code": r'''/* CVE-2024-2961 — glibc iconv 堆溢出。
 * malloc(128) + memcpy(160)。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    char src[192];
    memset(src, 'E', sizeof(src));
    memcpy(buf, src, 160);                /* 越界 32B */
    free(buf);
    return 0;
}
''',
    },
]
