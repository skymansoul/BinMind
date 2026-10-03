/* CVE-2020-10713 — GRUB2 引导器堆溢出 (BootHole 相关)
 *
 * 触发条件: GRUB2 解析配置文件时, 对 token 长度未做边界检查,
 * malloc(strlen(token)) 后 sprintf 写入更多数据。
 *
 * 测试目标: 常数偏移 + 分配器 padding 检查 —
 * 若偏移在 ptmalloc2 的 padding 区, 静态分析应识别为安全。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void parse_config_line(const char *token, const char *value) {
    size_t tok_len = strlen(token);
    size_t val_len = strlen(value);
    /* 仅分配 token 长度, 但后续操作使用了 token+value+separator */
    char *line = (char *)malloc(tok_len);
    if (!line) return;

    /* BUG: sprintf 写入超过 tok_len */
    sprintf(line, "%s=%s", token, value);
    printf("parsed: %s\n", line);
    free(line);
}

int main(int argc, char **argv) {
    if (argc < 3) return 1;
    parse_config_line(argv[1], argv[2]);
    return 0;
}
