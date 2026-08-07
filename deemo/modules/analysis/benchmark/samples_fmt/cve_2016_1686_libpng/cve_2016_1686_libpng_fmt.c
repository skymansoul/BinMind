/**
 * CVE-2016-1686 — libpng png_set_PLTE passes tEXt chunk to fprintf via log callback
 * 模式: callback_fmtstr
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

typedef void (*LogCb_v_2016_1686_libpng)(const char *);

static LogCb_v_2016_1686_libpng g_log_v_2016_1686_libpng;

void v_2016_1686_libpng_set_logger(LogCb_v_2016_1686_libpng cb) {
    g_log_v_2016_1686_libpng = cb;
}

void v_2016_1686_libpng_on_data(char *data) {
    if (g_log_v_2016_1686_libpng) g_log_v_2016_1686_libpng(data);  /* 回调使用原始data作为格式 */
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    v_2016_1686_libpng_set_logger((LogCb_v_2016_1686_libpng)printf);
    printf("=== v_2016_1686_libpng callback fmt test ===\n");
    v_2016_1686_libpng_on_data(argv[1]);
    return 0;
}

