"""FMT 语料库规格 — 15个格式化字符串漏洞样本 + 15个安全样本.

设计决策:
  - TP 覆盖: 直接用户输入格式串、栈缓冲拼接、堆缓冲格式串、
    可写缓冲 %n、间接来源、多调用点、条件来源等.
  - FP 覆盖: 常量格式串+参数匹配、常量格式串+参数不匹配(非格式化
    漏洞, 属参数错误)、snprintf 限长、位置参数、双重百分号转义、
    只读格式化函数(vsnprintf)、非格式化 printf 系列误配等.
  - truth: expected_vuln + mode.
"""

FMT_TP_SAMPLES = [
    {
        'id': 'fmt_tp_01_direct_user',
        'mode': 'printf(user_input) 直接用户输入格式串',
        'src': r'''
/* FMT-TP-01: printf(user_input) — 直接格式化字符串漏洞. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char buf[128];
    if (argc > 1) {
        strcpy(buf, argv[1]);
    } else {
        strcpy(buf, "hello %x %x %x");
    }
    printf(buf);
    printf("\n");
    return 0;
}
''',
    },
    {
        'id': 'fmt_tp_02_stack_concat',
        'mode': '栈上拼接后再作为格式串',
        'src': r'''
/* FMT-TP-02: snprintf 拼接入栈缓冲, 再 printf 该缓冲. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[256];
    snprintf(fmt, sizeof(fmt), "prefix:%s", argc > 1 ? argv[1] : "%s");
    printf(fmt, "x");
    return 0;
}
''',
    },
    {
        'id': 'fmt_tp_03_heap_fmt',
        'mode': '堆缓冲作为格式串',
        'src': r'''
/* FMT-TP-03: malloc 缓冲存放用户格式串后 printf. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *fmt = (char *)malloc(128);
    if (!fmt) return 1;
    strcpy(fmt, argc > 1 ? argv[1] : "stack %n");
    printf(fmt);
    free(fmt);
    return 0;
}
''',
    },
    {
        'id': 'fmt_tp_04_sprintf_write',
        'mode': 'sprintf 可写缓冲 + %n',
        'src': r'''
/* FMT-TP-04: sprintf(user_fmt, ...) 写入栈缓冲, %n 可写内存. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char out[64];
    char *fmt = argc > 1 ? argv[1] : "len=%n";
    sprintf(out, fmt);
    printf("%s\n", out);
    return 0;
}
''',
    },
    {
        'id': 'fmt_tp_05_indirect_arg',
        'mode': '格式串经参数传递到辅助函数',
        'src': r'''
/* FMT-TP-05: 格式串作参数传入 log_msg 再 printf. */
#include <stdio.h>
#include <string.h>

void log_msg(const char *fmt) {
    printf(fmt);
    printf("\n");
}

int main(int argc, char **argv) {
    char buf[64];
    strcpy(buf, argc > 1 ? argv[1] : "%d %d %s");
    log_msg(buf);
    return 0;
}
''',
    },
    {
        'id': 'fmt_tp_06_double_printf',
        'mode': 'printf 两次使用同一用户格式串',
        'src': r'''
/* FMT-TP-06: 两次 printf 同一用户格式串. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[64];
    strcpy(fmt, argc > 1 ? argv[1] : "%x%x");
    printf(fmt);
    printf(fmt);
    return 0;
}
''',
    },
    {
        'id': 'fmt_tp_07_conditional_fmt',
        'mode': '条件选择用户格式串',
        'src': r'''
/* FMT-TP-07: 条件分支选择格式串, 两条路径均来自用户. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char *fmt;
    char buf1[32], buf2[32];
    strcpy(buf1, argc > 1 ? argv[1] : "%s");
    strcpy(buf2, "%n%n");
    if (argc > 2) {
        fmt = buf1;
    } else {
        fmt = buf2;
    }
    printf(fmt, "x");
    return 0;
}
''',
    },
    {
        'id': 'fmt_tp_08_syslog_fmt',
        'mode': 'syslog 用户格式串',
        'src': r'''
/* FMT-TP-08: 用户格式串经包装函数进入 printf. */
#include <stdio.h>
#include <string.h>

void my_log(const char *fmt) {
    printf(fmt);
    printf("\n");
}

int main(int argc, char **argv) {
    char fmt[64];
    strcpy(fmt, argc > 1 ? argv[1] : "%s %d");
    my_log(fmt);
    return 0;
}
''',
    },
    {
        'id': 'fmt_tp_09_fscanf_style',
        'mode': '从文件/输入读入格式串',
        'src': r'''
/* FMT-TP-09: fgets 读入格式串后 printf. */
#include <stdio.h>
#include <string.h>

int main(void) {
    char fmt[128];
    if (fgets(fmt, sizeof(fmt), stdin) == NULL) {
        strcpy(fmt, "default %x");
    }
    printf(fmt);
    return 0;
}
''',
    },
    {
        'id': 'fmt_tp_10_nested_call',
        'mode': '嵌套调用: strlen(user) 后 format 拼接',
        'src': r'''
/* FMT-TP-10: 用户输入经计算进入格式串. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[256];
    const char *src = argc > 1 ? argv[1] : "%s%s%s";
    size_t n = strlen(src);
    memcpy(fmt, src, n);
    fmt[n] = 0;
    printf(fmt, "a", "b", "c");
    return 0;
}
''',
    },
    {
        'id': 'fmt_tp_11_loop_write',
        'mode': '循环内逐段拼接用户输入为格式串',
        'src': r'''
/* FMT-TP-11: 循环拼接形成格式串. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[128] = "";
    const char *seg = argc > 1 ? argv[1] : "%d";
    for (int i = 0; i < 4 && strlen(fmt) < 100; i++) {
        strcat(fmt, seg);
    }
    printf(fmt, 1, 2, 3, 4);
    return 0;
}
''',
    },
    {
        'id': 'fmt_tp_12_offset_leak',
        'mode': '位置参数 %N$x 泄露',
        'src': r'''
/* FMT-TP-12: 用户格式串含位置参数, 用于栈泄露. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[64];
    strcpy(fmt, argc > 1 ? argv[1] : "%%7$llx");
    printf(fmt);
    return 0;
}
''',
    },
    {
        'id': 'fmt_tp_13_width_leak',
        'mode': '宽度/精度字段泄露 (%.N$x)',
        'src': r'''
/* FMT-TP-13: 宽度参数泄露. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[64];
    strcpy(fmt, argc > 1 ? argv[1] : "%2$.*3$s");
    printf(fmt, "a", "b", 8);
    return 0;
}
''',
    },
    {
        'id': 'fmt_tp_14_wrapper_func',
        'mode': '包装函数内 printf(fmt) 透传',
        'src': r'''
/* FMT-TP-14: print_red(fmt) 包装后透传用户格式串. */
#include <stdio.h>
#include <string.h>

void print_red(const char *fmt) {
    printf(fmt);
}

int main(int argc, char **argv) {
    char fmt[64];
    strcpy(fmt, argc > 1 ? argv[1] : "%s");
    print_red(fmt);
    return 0;
}
''',
    },
    {
        'id': 'fmt_tp_15_got_overwrite',
        'mode': '%n 组合利用 (可写目标)',
        'src': r'''
/* FMT-TP-15: sprintf(user_fmt) 中 %n 写已释放/可写区域. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char out[32];
    char *fmt = (char *)malloc(64);
    if (!fmt) return 1;
    strcpy(fmt, argc > 1 ? argv[1] : "%n");
    sprintf(out, fmt);
    free(fmt);
    printf("%s\n", out);
    return 0;
}
''',
    },
]

FMT_FP_SAMPLES = [
    {
        'id': 'fmt_fp_01_const_match',
        'mode': '常量格式串 + 参数完全匹配',
        'src': r'''
/* 安全: 常量格式串 "%s %d" 与实参匹配. */
#include <stdio.h>

int main(void) {
    printf("%s %d\n", "hello", 42);
    return 0;
}
''',
    },
    {
        'id': 'fmt_fp_02_const_mismatch',
        'mode': '常量格式串但参数不匹配 (参数错误非格式化漏洞)',
        'src': r'''
/* 安全: 常量格式串, 参数缺失 — 属参数错误, 非格式化字符串漏洞. */
#include <stdio.h>

int main(void) {
    printf("%s %d\n", "only-one");
    return 0;
}
''',
    },
    {
        'id': 'fmt_fp_03_snprintf_bounded',
        'mode': 'snprintf 限长 + 常量格式串',
        'src': r'''
/* 安全: snprintf 显式限长, 常量格式串. */
#include <stdio.h>

int main(void) {
    char buf[32];
    snprintf(buf, sizeof(buf), "v=%d", 7);
    printf("%s\n", buf);
    return 0;
}
''',
    },
    {
        'id': 'fmt_fp_04_double_percent',
        'mode': '双重百分号转义 (无格式语义)',  # 口径: 测试语料中 100%% 为 C 格式转义, 非检测结果宣称
        'src': r'''
/* 安全: "100%%" 中 %% 为转义, 无实际说明符. */
#include <stdio.h>

int main(void) {
    printf("progress 100%% done\n");
    return 0;
}
''',  # 口径: 上述 C 语料中 100%% 为格式转义, 非检测结果宣称
    },
    {
        'id': 'fmt_fp_05_positional_const',
        'mode': '常量位置参数格式串',
        'src': r'''
/* 安全: 常量格式串含位置参数, 实参存在. */
#include <stdio.h>

int main(void) {
    printf("%2$d %1$d\n", 10, 20);
    return 0;
}
''',
    },
    {
        'id': 'fmt_fp_06_vsnprintf_ro',
        'mode': 'vsnprintf 常量格式串写入限长缓冲',
        'src': r'''
/* 安全: vsnprintf 限长 + 常量格式串. */
#include <stdio.h>
#include <stdarg.h>

void fmt(char *out, size_t n, const char *f, ...) {
    va_list ap;
    va_start(ap, f);
    vsnprintf(out, n, f, ap);
    va_end(ap);
}

int main(void) {
    char buf[32];
    fmt(buf, sizeof(buf), "%d-%s", 3, "x");
    printf("%s\n", buf);
    return 0;
}
''',
    },
    {
        'id': 'fmt_fp_07_const_no_args',
        'mode': '常量格式串无参数',
        'src': r'''
/* 安全: printf("literal") 无参数无说明符. */
#include <stdio.h>

int main(void) {
    printf("literal message\n");
    return 0;
}
''',
    },
    {
        'id': 'fmt_fp_08_percent_in_data',
        'mode': '数据中的百分号被误判 (字符串拼接)',
        'src': r'''
/* 安全: 数据经 %s 传入, 数据内百分号无格式语义. */
#include <stdio.h>

int main(void) {
    printf("rate: %s\n", "50%");
    return 0;
}
''',
    },
    {
        'id': 'fmt_fp_09_const_escaped',
        'mode': '转义序列 %d%% 常量',
        'src': r'''
/* 安全: "%%d" 转义后无说明符, 常量安全. */
#include <stdio.h>

int main(void) {
    printf("literal %%d\n");
    return 0;
}
''',
    },
    {
        'id': 'fmt_fp_10_syslog_const',
        'mode': 'syslog 常量格式串',
        'src': r'''
/* 安全: syslog 使用常量格式串. */
#include <stdio.h>

void my_log(const char *msg) {
    printf("LOG: %s\n", msg);
}

int main(void) {
    my_log("started");
    return 0;
}
''',
    },
    {
        'id': 'fmt_fp_11_const_wrapper',
        'mode': '包装函数透传常量格式串',
        'src': r'''
/* 安全: 包装函数 printf(fmt) 但 fmt 恒为常量. */
#include <stdio.h>

void show(const char *fmt) {
    printf(fmt);
}

int main(void) {
    show("value=%d\n");
    return 0;
}
''',
    },
    {
        'id': 'fmt_fp_12_fprintf_stderr_const',
        'mode': 'fprintf(stderr, 常量)',
        'src': r'''
/* 安全: fprintf 到 stderr 的常量格式串. */
#include <stdio.h>

int main(void) {
    fprintf(stderr, "error %d occurred\n", 5);
    return 0;
}
''',
    },
    {
        'id': 'fmt_fp_13_sprintf_const_match',
        'mode': 'sprintf 常量格式串 + 匹配参数 (无 %n)',
        'src': r'''
/* 安全: sprintf 常量格式串, 缓冲足够. */
#include <stdio.h>

int main(void) {
    char out[64];
    sprintf(out, "user=%s id=%d", "alice", 1);
    printf("%s\n", out);
    return 0;
}
''',
    },
    {
        'id': 'fmt_fp_14_nonfmt_function',
        'mode': '非格式化函数误配 (puts/strlen)',
        'src': r'''
/* 安全: puts/strlen 不是格式化函数. */
#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[64];
    strcpy(buf, "plain %s");
    puts(buf);
    printf("%zu\n", strlen(buf));
    return 0;
}
''',
    },
    {
        'id': 'fmt_fp_15_const_multiline',
        'mode': '多行常量格式串拼接',
        'src': r'''
/* 安全: 相邻字符串字面量拼接为常量格式串. */
#include <stdio.h>

int main(void) {
    printf("line1 %d "
           "line2 %s\n", 1, "x");
    return 0;
}
''',
    },
]
