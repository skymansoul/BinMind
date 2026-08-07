/*
 * CVE-2021-3156 (Baron Samedit) 模式复刻 — sudo heap overflow
 * 真实漏洞: sudoedit 在 argv 以单字符结尾时未正确追加 NULL,
 *           触发堆越界写, 可本地提权 (CVE-2021-3156)
 * 触发条件: 命令行参数以 '\' 单字符结尾
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ARGS 8

char **build_argv(char **user_args, int n) {
    /* 缺陷: 为每个参数分配 strlen+1, 但末尾追加 '\\' 时
       复制 len+2 字节 (NULL 终止 + 转义字符) */
    char **argv = (char **)malloc((n + 1) * sizeof(char *));
    if (!argv) return NULL;
    int i;
    for (i = 0; i < n; i++) {
        size_t len = strlen(user_args[i]);
        char *copy = (char *)malloc(len + 2);
        if (!copy) continue;
        memcpy(copy, user_args[i], len + 1);   /* len+1 已含 NULL */
        if (user_args[i][len - 1] == '\\') {
            copy[len] = '\\';                   /* 越界写: 超出 len+1 */
            copy[len + 1] = 0;
        }
        argv[i] = copy;
    }
    argv[n] = NULL;
    return argv;
}

int main(int argc, char **argv) {
    char *args[2];
    args[0] = "sudoedit";
    args[1] = "file\\";                          /* 单字符反斜杠结尾 */
    char **built = build_argv(args, 2);
    if (built) {
        int i;
        for (i = 0; i < 2; i++) if (built[i]) free(built[i]);
        free(built);
    }
    return 0;
}
