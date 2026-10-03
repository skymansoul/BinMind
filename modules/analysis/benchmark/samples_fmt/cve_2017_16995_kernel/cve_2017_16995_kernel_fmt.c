/**
 * CVE-2017-16995 — Linux BPF verifier passes user-controlled value to print_bpf_insn
 * 模式: bpf_fmtstr
 *
 * 样本设计: 精简化复现格式字符串漏洞核心机制.
 * 对静态分析的挑战:
 *   1. 格式字符串来源需追踪 (寄存器/栈/全局/跨函数)
 *   2. 字面量格式字符串应被过滤 (误报控制)
 *   3. 跨函数传播需参数追踪
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*LogCb_v_2017_16995_kernel)(const char *);

static LogCb_v_2017_16995_kernel g_log_v_2017_16995_kernel;

void v_2017_16995_kernel_set_logger(LogCb_v_2017_16995_kernel cb) {
    g_log_v_2017_16995_kernel = cb;
}

void v_2017_16995_kernel_on_data(char *data) {
    if (g_log_v_2017_16995_kernel) g_log_v_2017_16995_kernel(data);  /* 回调使用原始data作为格式 */
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    v_2017_16995_kernel_set_logger((LogCb_v_2017_16995_kernel)printf);
    printf("=== v_2017_16995_kernel callback fmt test ===\n");
    v_2017_16995_kernel_on_data(argv[1]);
    return 0;
}

