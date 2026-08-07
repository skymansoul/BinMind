/*
 * CVE-2021-3156 — Sudo "Baron Samedit" 堆溢出 (简化复现)
 * sudo 1.8.2 ~ 1.8.31p2 / 1.9.0 ~ 1.9.5p1 中 sudoedit -s 模式的堆溢出.
 *
 * 漏洞机制:
 *   set_cmnd() 函数在处理命令行参数时:
 *     1. 计算 from 参数的大小 (包括转义字符)
 *     2. 以 from 的大小为 args 分配 user_args 缓冲区
 *     3. 实际向 user_args 写入时, 未转义的字符数可能超过 from 的大小
 *     4. 当 '\\' 出现在参数末尾时, 特殊逻辑导致 off-by-one 或更大溢出
 *
 * 具体触发: sudoedit -s 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\'
 *   → 最后一个反斜杠被错误处理后, user_args 写入越界.
 *
 * 本文件简化: 模拟 set_cmnd() 的参数处理和缓冲区溢出逻辑.
 *
 * 影响: 本地提权 (任何用户 → root). 多个 Linux 发行版受影响.
 * 修复: sudo 1.9.5p2 — 重新实现 set_cmnd() 参数处理逻辑.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * 漏洞模拟: 处理命令行参数的转义逻辑
 *
 * 原漏洞中, set_cmnd() 先扫描参数计算 size_needed,
 * 然后用 size_needed 分配 user_args, 最后逐个字符拷贝.
 * 但扫描逻辑和拷贝逻辑对转义字符的处理不一致,
 * 导致实际写入大小 > 分配大小.
 */
char *set_cmnd_vulnerable(const char *user_input_shellarg) {
    size_t arg_len      = strlen(user_input_shellarg);
    size_t size_needed  = arg_len + 1; /* +1 for null terminator */
    char  *user_args    = (char *)malloc(size_needed);

    if (!user_args) return NULL;

    /*
     * 漏洞: 拷贝时, 若输入以反斜杠结尾 (如 'A'*N + '\\'),
     *       原始代码会额外写入一个 '\\' 或跳过 null 终止符,
     *       导致写入 size_needed+1 (或更多) 字节.
     *
     * 原始 Qualys exploit 利用此 off-by-one/off-by-two
     * 写覆盖相邻堆块的 size 字段实现提权.
     */
    size_t write_idx = 0;
    for (size_t i = 0; i < arg_len; i++) {
        if (user_input_shellarg[i] == '\\' && i + 1 == arg_len) {
            /* 末尾反斜杠的特殊处理 — 漏洞所在!
             * 原始代码: 写入 '\\' 后退出, 但循环外还有逻辑
             * 导致 null 终止符被越界写入. */
            user_args[write_idx++] = '\\';
            /* BUG: 原始代码在此处设置了一些flag,
             * 然后循环结束后又写入了一次字符,
             * 导致 write_idx >= size_needed 时越界. */
        }
        user_args[write_idx++] = user_input_shellarg[i];
    }

    /* null 终止 — 若 write_idx >= size_needed, 越界! */
    user_args[write_idx] = '\0'; /* 溢出写入! */

    printf("  size_needed=%zu, actually_written=%zu (overflow=%zd)\n",
           size_needed, write_idx + 1, (ssize_t)(write_idx + 1) - (ssize_t)size_needed);
    return user_args;
}

int main(void) {
    /*
     * 攻击者构造 sudoedit -s 的恶意参数:
     *   反斜杠结尾 → 触发转义处理逻辑错误
     */
    char evil_arg[128];
    memset(evil_arg, 'A', 64);
    evil_arg[64] = '\\';
    evil_arg[65] = '\0';

    printf("[*] Sudo Baron Samedit heap overflow test\n");
    printf("  evil arg: %s (len=%zu)\n", evil_arg, strlen(evil_arg));

    char *result = set_cmnd_vulnerable(evil_arg);
    if (result) {
        printf("[!] Vulnerable set_cmnd executed\n");
        free(result);
    }
    return 0;
}
