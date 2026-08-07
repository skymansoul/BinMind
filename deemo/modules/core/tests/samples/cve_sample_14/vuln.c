/* CVE-2022-0185 (模拟) — Linux fsconfig 堆溢出
 * 真实: kernel 5.1+, fs/fs_context.c: legacy_parse_param slub 溢出
 * 漏洞: 字符串长度计算与实际拷贝不一致 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct param_info {
    char *key;
    size_t key_len;
    char *value;
};

void parse_fs_param(struct param_info *p, const char *input) {
    size_t total = 64;
    char *buf = (char *)malloc(total);
    if (!buf) return;
    /* 漏洞: 未检查实际 input 长度, 直接 snprintf */
    snprintf(buf, 256, "key=%s,val=%s", p->key, p->value);
    /* snprintf 的 size 参数 256 > 实际分配 64 */
    printf("%s\n", buf);
    free(buf);
}

int main(void) {
    struct param_info pi = {"long_option_name", 17, "very_long_value_string_here_overflow"};
    parse_fs_param(&pi, "");
    return 0;
}
