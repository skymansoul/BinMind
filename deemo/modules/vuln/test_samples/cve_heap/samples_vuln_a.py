# coding: utf-8
# 创建: 2026-05-12  |  语料数据 A——TP 样本 1-6
#
"""TP 样本数据 (cve_2014_0038 ~ cve_2020_10713). 仅数据, 无逻辑."""

SAMPLES_VULN_A = [
    {
        "id": "cve_2014_0038_recvfrom",
        "cve": "CVE-2014-0038",
        "title": "Linux kernel AF_PACKET recvfrom heap overflow (integer underflow)",
        "pattern": "recv 长度由 user_len-8 推导, user_len 可小至 1, 下溢为巨大无符号数",
        "trigger": "user_len < 8 时 user_len-8 回绕 → 写入远超分配",
        "why": "写入长度 m=user_len-8 无上界约束, 且与分配长度不同源",
        "code": r'''/* CVE-2014-0038 — recvfrom 整数下溢导致堆溢出 (kernel AF_PACKET)。
 * 分配 user_len, 写入 user_len-8; user_len<8 时下溢为巨大值。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    size_t user_len = 64;
    if (argc > 1) user_len = strlen(argv[1]);
    char *buf = (char *)malloc(user_len);
    if (!buf) return 1;
    size_t m = user_len - 8;              /* 下溢点 */
    memcpy(buf, argv[2], m);              /* 越界写入 */
    free(buf);
    return 0;
}
''',
    },
    {
        "id": "cve_2015_0240_samba",
        "cve": "CVE-2015-0240",
        "title": "Samba netlogon heap overflow (length mismatch)",
        "pattern": "分配 len, 写入 len+16, 长度错配",
        "trigger": "len 任意取值, len+16 恒大于 len",
        "why": "写入量与分配量算术相关但系数 1 常数差 16",
        "code": r'''/* CVE-2015-0240 — Samba netlogon 参数长度错配 → memcpy 越界。
 * 分配 len, 写入 len+16。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    size_t len = 64;
    if (argc > 1) len = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc(len);
    if (!buf) return 1;
    char src[64];
    memset(src, 'B', sizeof(src));
    memcpy(buf, src, len + 16);           /* 恒越界 */
    free(buf);
    return 0;
}
''',
    },
    {
        "id": "cve_2017_1000253_pie",
        "cve": "CVE-2017-1000253",
        "title": "PIE/loader ELF metadata heap overflow (constant overflow)",
        "pattern": "malloc(64) 后 memcpy(96)",
        "trigger": "写入常量 96 > 可用大小",
        "why": "最基础常量越界, 任意检测器应检出",
        "code": r'''/* CVE-2017-1000253 — PIE 加载器堆溢出 (常量越界模式)。
 * malloc(64) + memcpy(96)。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    char src[96];
    memset(src, 'A', sizeof(src));
    memcpy(buf, src, 96);                 /* 越界 32B */
    free(buf);
    return 0;
}
''',
    },
    {
        "id": "cve_2018_1000001_glibc",
        "cve": "CVE-2018-1000001",
        "title": "glibc realpath heap overflow (unbounded strcpy)",
        "pattern": "malloc(strlen(p)+2) 后 strcpy 无界写入",
        "trigger": "realpath 展开后长度超预期, strcpy 无上界",
        "why": "strcpy 无界 API, 写入量不可静态确定",
        "code": r'''/* CVE-2018-1000001 — glibc realpath 堆溢出 (strcpy 无界)。
 * 分配随路径长度增长, strcpy 无界写入。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    size_t plen = strlen(argv[1]);
    char *buf = (char *)malloc(plen + 2);
    if (!buf) return 1;
    strcpy(buf, argv[1]);                 /* 无界 → 越界 */
    free(buf);
    return 0;
}
''',
    },
    {
        "id": "cve_2019_15846_rsync",
        "cve": "CVE-2019-15846",
        "title": "rsync parse_arguments integer overflow to heap write",
        "pattern": "calloc(n,1) 后 memcpy(n*2)",
        "trigger": "n 用户可控, n*2 恒大于分配 n",
        "why": "整数乘法的写入系数 2 倍于分配",
        "code": r'''/* CVE-2019-15846 — rsync 整数溢出 → 堆越界 (calloc 乘积)。
 * 分配 n, 写入 2n。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    size_t n = 32;
    if (argc > 1) n = (size_t)atoi(argv[1]);
    char *buf = (char *)calloc(n, 1);
    if (!buf) return 1;
    char src[128];
    memset(src, 'C', sizeof(src));
    memcpy(buf, src, n * 2);              /* 2 倍越界 */
    free(buf);
    return 0;
}
''',
    },
    {
        "id": "cve_2020_10713_grub",
        "cve": "CVE-2020-10713",
        "title": "grub2 setparams heap overflow (bad enough fixed-size write)",
        "pattern": "malloc(32) 后 memset(64)",
        "trigger": "固定写入 64 > 分配 32 的可用空间",
        "why": "固定常量越界 (R4 可证明)",
        "code": r'''/* CVE-2020-10713 — grub2 堆溢出 (固定大小写入越界)。
 * malloc(32) + memset(64)。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    memset(buf, 0x41, 64);                /* 越界 32B */
    free(buf);
    return 0;
}
''',
    },
]
