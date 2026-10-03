/*
 * CVE-2021-3156 — Sudo Heap Overflow (Baron Samedit) (CWE-122)
 *
 * Sudo 1.8.2 ~ 1.8.31p2 / 1.9.0 ~ 1.9.5p1: sudoedit -s 模式下的堆溢出.
 * set_cmnd() 函数在解析命令行参数时, 未正确处理反斜杠转义的
 * '\\' 结尾行, 导致 user_args 大小计算不正确,
 * 后续 memcpy 拷贝的字节数超出分配的堆空间.
 *
 * 文献: Qualys, "Baron Samedit: Heap-based buffer overflow in Sudo", Jan 2021.
 * CVSS: 7.8 (High), CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
 */

#include <stdlib.h>
#include <string.h>

/* 模拟 sudo 的 set_cmnd 参数处理逻辑 */
static char *parse_cmdline(const char *cmdline, size_t len) {
    size_t alloc_sz;
    char *buf;

    /* Step 1: 计算需要的大小 — 遍历参数, 展开转义 */
    size_t computed = 0;
    size_t i = 0;
    while (i < len) {
        if (cmdline[i] == '\\' && i + 1 < len) {
            i += 2;
            computed += 1; /* 转义字符占1字节 */
        } else {
            i += 1;
            computed += 1;
        }
    }
    alloc_sz = computed + 1;

    /* [VULN] 当行以单独的反斜杠结尾时 (cmdline[len-1] == '\\'),
     * 上述循环将 i+1 < len 判定为 false, 已处理了 i+1 == len 的情况,
     * 但 i 只前进1 (跳过\) 而 computed 没增加 — 导致 computed < 实际需要
     */

    buf = (char *)malloc(alloc_sz);
    if (!buf) return NULL;

    /* Step 2: 实际拷贝 — 使用不同的循环, 可能多拷贝 */
    size_t out = 0;
    for (i = 0; i < len; i++) {
        if (cmdline[i] == '\\' && i + 1 < len) {
            buf[out++] = cmdline[++i]; /* 写转义后的字符 */
        } else {
            buf[out++] = cmdline[i]; /* [VULN] out 可能超过 alloc_sz-1 */
        }
    }
    buf[out] = '\0';

    return buf;
}

int main(void) {
    /* 模拟: sudoedit -s '\\' 'bar' — 以反斜杠结尾触发off-by-one→off-by-N */
    char cmdline[256];
    memset(cmdline, '\\', 255);
    cmdline[254] = 'A'; /* 最后一个不是反斜杠, 但有大量单反斜杠 */
    cmdline[255] = '\0';

    char *result = parse_cmdline(cmdline, 255);
    if (result) {
        free(result);
    }
    return 0;
}
