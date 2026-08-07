/*
 * CVE-2020-10713 — GRUB2 BootHole: 堆溢出→SecureBoot 绕过 (CWE-122)
 *
 * GRUB2 2.04 之前: grub_cmd_authenticate 中的缓冲区溢出,
 * 配置文件中的超大字符串通过 grub_malloc 分配后, 未检查拷贝边界.
 *
 * 文献: Eclypsium, "Boothole: There's a Hole in the Boot", Jul 2020.
 * CVSS: 8.2 (High), CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
 */

#include <stdlib.h>
#include <string.h>

#define MAX_CFG_LINE 4096

int config_parse_line(const char *line) {
    size_t len = strlen(line);

    /* [VULN] len 可能 > MAX_CFG_LINE, 但分配使用 len */
    char *buf = (char *)malloc(len + 1);
    if (!buf) return -1;

    /* 拷贝 — 使用 len, 和分配一致 (看似安全) */
    strcpy(buf, line); /* 问题: strcpy 不检查边界 */

    /* [VULN] 但后续 token 化时, 将结果写入固定大小栈缓冲区 */
    char token_buf[256];
    /* 如果配置行的某部分 > 256, 栈缓冲区溢出 */
    char *space = strchr(buf, ' ');
    if (space) {
        size_t snip_len = space - buf;
        if (snip_len >= sizeof(token_buf))
            snip_len = sizeof(token_buf) - 1;
        memcpy(token_buf, buf, snip_len);
        token_buf[snip_len] = '\0';
    }

    free(buf);
    return 0;
}

int main(void) {
    /* 模拟超长配置行 */
    char line[5000];
    memset(line, 'A', 4999);
    line[4999] = '\0';
    return config_parse_line(line);
}
