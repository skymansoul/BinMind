/* CVE-2021-3156 — sudo Baron Samedit 堆溢出
 *
 * 触发条件: sudoedit 模式下, 命令行参数中的反斜杠转义处理
 * 导致 set_cmnd() 中堆缓冲区溢出。关键是:
 * - user_args 被拷贝到堆缓冲区
 * - 拷贝量基于转义序列数量, 与原始分配大小不一致
 *
 * 测试目标: 多路径的 size 约束分析 — 不同的命令行参数路径
 * 导致不同的 size 计算结果, 需要路径敏感分析才能区分。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct sudo_context {
    char *cmnd;
    int cmnd_size;
};

static int count_escapes(const char *s) {
    int n = 0;
    while (*s) { if (*s == '\\') n++; s++; }
    return n;
}

static void set_cmnd(struct sudo_context *ctx, const char *user_args, int len) {
    int escapes;
    int new_size;

    if (len <= 0) return;

    /* 分配时忽略了转义字符的额外空间 */
    ctx->cmnd = (char *)malloc(len + 1);
    if (!ctx->cmnd) return;
    ctx->cmnd_size = len + 1;

    escapes = count_escapes(user_args);
    new_size = len + escapes;  /* 实际需要的空间可能是 len + escapes */

    /* BUG: 若 escapes > 0, new_size 可能 > cmnd_size */
    memcpy(ctx->cmnd, user_args, new_size);
    ctx->cmnd[new_size] = '\0';
}

int main(int argc, char **argv) {
    struct sudo_context ctx = {0};
    if (argc < 2) return 1;
    set_cmnd(&ctx, argv[1], (int)strlen(argv[1]));
    free(ctx.cmnd);
    return 0;
}
