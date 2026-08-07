/* CVE-2022-0185 — Linux kernel fs_context heap overflow (userspace simulation)
 * 原始漏洞: legacy_parse_param 中整数溢出导致分配过小 → 后续写入溢出.
 * 本文件模拟核心模式: size + len 可能溢出 size_t / unsigned int.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* Userspace simulation of kernel fs_context parsing bug */
int parse_param(size_t option_size, size_t val_len, const char *val) {
    /* bug: option_size + val_len may overflow → allocation too small */
    size_t total = option_size + val_len + 1;
    if (total < option_size) { /* integer overflow check (correct but in kernel it was missing) */
        fprintf(stderr, "overflow detected\n");
    }
    char *buf = (char *)malloc(total);
    if (!buf) return -1;
    memcpy(buf, val, val_len);          /* fill value */
    buf[val_len] = '=';                  /* separator */
    memcpy(buf + val_len + 1, val, option_size); /* fill option (overflow if total wrapped) */
    free(buf);
    return 0;
}

int main(void) {
    /* Trigger: large values to test overflow detection */
    parse_param(0xFFFFFFFFFFFFFF00ULL, 0x200, "AAAA");
    return 0;
}
