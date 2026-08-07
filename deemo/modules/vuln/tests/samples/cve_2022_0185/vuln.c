/* CVE-2022-0185 — Linux kernel fscontext 堆溢出 (CAP_SYS_ADMIN escape)
 *
 * 触发条件: legacy_parse_param 中, 字符串长度计算错误导致
 * kmalloc 分配偏小, 后续 memcpy 越界。
 *
 * 测试目标: 字符串长度推导 — strlen(input) 返回 N,
 * 但后续内存操作使用 N+len(prefix) > allocated。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fs_context {
    char *source;
    size_t source_len;
};

static void legacy_parse(struct fs_context *fc, const char *param, size_t param_len) {
    const char prefix[] = "legacy:";
    size_t total_len;

    total_len = strlen(prefix) + param_len;

    /* BUG: 只分配了 param_len, 实际需要 total_len */
    fc->source = (char *)malloc(param_len);
    if (!fc->source) return;
    fc->source_len = param_len;

    /* sprintf 写入 total_len 字节到 param_len 大小的 buffer */
    snprintf(fc->source, total_len + 1, "%s%s", prefix, param);
}

int main(int argc, char **argv) {
    struct fs_context fc = {0};
    if (argc < 2) return 1;
    legacy_parse(&fc, argv[1], strlen(argv[1]));
    free(fc.source);
    return 0;
}
