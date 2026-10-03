"""FPE 格式字符串样本集 — 15 CVE 复现 + 8 良性对照.

创建: 2025-01-13
每个样本: (id, 名称, 源码, 说明)
  expected='vuln'  → 用户可控格式串, 检测必须命中
  expected='clean' → 常量格式串, 检测应滤除

CVE 样本为真实漏洞的最小化复现, 保留"用户输入流向格式参数"的失衡
模式。良性对照组覆盖 FPE 核心滤除场景:
  .rdata 常量池溯源 (直接/经局部变量/经全局数组间接传递)
"""

import textwrap


def _c(body: str) -> str:
    """去掉公共缩进, 生成完整 C 源."""
    return textwrap.dedent(body)


FMT_SAMPLES = [
    (
        "FMT-01",
        "microsoft_fmt",
        _c("""
            /* 格式串漏洞复现: 用户输入直接作为 printf 格式串. */
            #include <stdio.h>

            static void handle(char *user) {
                printf(user);            /* 格式串 = 用户输入 */
            }

            int main(int argc, char **argv) {
                handle(argv[1]);
                return 0;
            }
        """),
        "用户输入 argv 直接作为 printf 格式串",
    ),
    (
        "FMT-02",
        "fprintf_fmt",
        _c("""
            /* fprintf 格式串漏洞复现: 用户输入作格式串. */
            #include <stdio.h>

            static void log_msg(char *user) {
                fprintf(stderr, user);   /* 用户输入作格式串 */
            }

            int main(int argc, char **argv) {
                log_msg(argv[1]);
                return 0;
            }
        """),
        "fprintf 格式串来自用户参数",
    ),
    (
        "FMT-03",
        "sprintf_fmt",
        _c("""
            /* sprintf 格式串漏洞复现: 用户输入作格式串, 可写越界. */
            #include <stdio.h>
            #include <stdlib.h>

            static char *fmt_sink(char *user) {
                char *out = malloc(64);
                sprintf(out, user);      /* 格式串 = 用户输入 */
                return out;
            }

            int main(int argc, char **argv) {
                free(fmt_sink(argv[1]));
                return 0;
            }
        """),
        "sprintf 格式串来自用户参数",
    ),
    (
        "FMT-04",
        "read_fmt",
        _c("""
            /* 格式串漏洞复现: read 读取内容作 printf 格式串. */
            #include <stdio.h>
            #include <unistd.h>

            int main(void) {
                char buf[128];
                int n = read(0, buf, 127);
                buf[n] = 0;
                printf(buf);             /* 格式串 = 网络/管道输入 */
                return 0;
            }
        """),
        "read 读取内容作为 printf 格式串",
    ),
    (
        "FMT-05",
        "gets_fmt",
        _c("""
            /* 格式串漏洞复现: gets 读取内容作 printf 格式串. */
            #include <stdio.h>

            int main(void) {
                char buf[256];
                gets(buf);               /* 用户输入 */
                printf(buf);             /* 格式串 = 用户输入 */
                return 0;
            }
        """),
        "gets 读取内容作为 printf 格式串",
    ),
    (
        "FMT-06",
        "param_fmt",
        _c("""
            /* 格式串经函数参数传递 — 调用方可控. */
            #include <stdio.h>

            static void emit(const char *fmt, int v) {
                printf(fmt, v);          /* fmt 来自参数 */
            }

            int main(int argc, char **argv) {
                emit(argv[1], argc);
                return 0;
            }
        """),
        "printf 格式串为函数参数, 调用方传用户输入",
    ),
    (
        "FMT-07",
        "snprintf_fmt",
        _c("""
            /* snprintf 格式串来自用户参数. */
            #include <stdio.h>

            static void pack(char *user) {
                char out[64];
                snprintf(out, 64, user); /* 格式串 = 用户输入 */
            }

            int main(int argc, char **argv) {
                pack(argv[1]);
                return 0;
            }
        """),
        "snprintf 格式串来自用户参数",
    ),
    (
        "FMT-08",
        "strcpy_fmt",
        _c("""
            /* 格式串经 strcpy 拼接后使用 — 用户可控. */
            #include <stdio.h>
            #include <string.h>

            int main(int argc, char **argv) {
                char fmt[128];
                strcpy(fmt, argv[1]);    /* 用户输入入缓冲 */
                printf(fmt);             /* 格式串 = 用户输入 */
                return 0;
            }
        """),
        "strcpy 拷贝用户输入后作为格式串",
    ),
    (
        "FMT-09",
        "vprintf_fmt",
        _c("""
            /* vprintf 格式串来自用户参数. */
            #include <stdarg.h>
            #include <stdio.h>

            static void vemit(char *fmt, ...) {
                va_list ap;
                va_start(ap, fmt);
                vprintf(fmt, ap);        /* 格式串 = 参数 */
                va_end(ap);
            }

            int main(int argc, char **argv) {
                vemit(argv[1]);
                return 0;
            }
        """),
        "vprintf 格式串来自用户参数",
    ),
    (
        "FMT-10",
        "reassign_fmt",
        _c("""
            /* 格式串变量被用户输入覆盖后使用. */
            #include <stdio.h>

            int main(int argc, char **argv) {
                char *fmt = "fixed";
                if (argc > 1) fmt = argv[1];  /* 覆盖为用户输入 */
                printf(fmt);
                return 0;
            }
        """),
        "格式串变量被用户输入覆盖",
    ),
    (
        "FMT-11",
        "fprintf_stdout_fmt",
        _c("""
            /* fprintf(stdout) 格式串漏洞复现: 用户输入作格式串. */
            #include <stdio.h>

            static void send(int fd, char *user) {
                fprintf(stdout, user);   /* 格式串 = 用户输入 */
            }

            int main(int argc, char **argv) {
                send(1, argv[1]);
                return 0;
            }
        """),
        "fprintf(stdout) 格式串来自用户参数",
    ),
    (
        "FMT-12",
        "fgets_fmt",
        _c("""
            /* fgets 读取内容作为格式串. */
            #include <stdio.h>

            int main(void) {
                char buf[128];
                if (!fgets(buf, sizeof(buf), stdin)) return 0;
                printf(buf);             /* 格式串 = 用户输入 */
                return 0;
            }
        """),
        "fgets 读取内容作为 printf 格式串",
    ),
    (
        "FMT-13",
        "env_fmt",
        _c("""
            /* 格式串来自环境变量. */
            #include <stdio.h>
            #include <stdlib.h>

            int main(void) {
                char *fmt = getenv("FMT");   /* 环境可控 */
                printf(fmt);
                return 0;
            }
        """),
        "getenv 返回内容作为格式串",
    ),
    (
        "FMT-14",
        "argv_fmt",
        _c("""
            /* argv 直接作格式串. */
            #include <stdio.h>

            int main(int argc, char **argv) {
                printf(argv[argc - 1]);  /* 最后一个参数作格式串 */
                return 0;
            }
        """),
        "argv 元素直接作 printf 格式串",
    ),
    (
        "FMT-15",
        "syslog_fmt",
        _c("""
            /* syslog 格式串来自用户参数. */
            #include <stdio.h>

            static void syslog_fmt(char *user) {
                printf("[syslog] ");
                printf(user);            /* 格式串 = 用户输入 */
            }

            int main(int argc, char **argv) {
                syslog_fmt(argv[1]);
                return 0;
            }
        """),
        "syslog 样式日志, 格式串来自用户输入",
    ),
]

FMT_CLEAN_SAMPLES = [
    (
        "FMT-C1",
        "direct_const",
        _c("""
            /* 良性: printf 格式串为直接常量. */
            #include <stdio.h>

            int main(int argc, char **argv) {
                printf("Hello %s, argc=%d\\n", argv[0], argc);
                return 0;
            }
        """),
        ".rdata 常量池溯源, 直接 lea [rip+off]",
    ),
    (
        "FMT-C2",
        "local_var_const",
        _c("""
            /* 良性: 常量格式串经局部变量传递, 距调用点超过回溯窗口. */
            #include <stdio.h>

            int main(int argc, char **argv) {
                const char *fmt = "value: %d\\n";
                int sum = 0;
                for (int i = 0; i < argc; i++) sum += i;   /* 插入指令 */
                sum += argc;
                printf(fmt, sum);        /* fmt 为局部常量引用 */
                return sum != 0;
            }
        """),
        "常量经局部变量/栈槽传递, FPE 全链标签可解析",
    ),
    (
        "FMT-C3",
        "global_const_array",
        _c("""
            /* 良性: 静态全局常量数组作格式串. */
            #include <stdio.h>

            static const char g_fmt[] = "result: %d\\n";

            int main(int argc, char **argv) {
                printf(g_fmt, argc);
                return 0;
            }
        """),
        "全局常量数组溯源为 .rdata",
    ),
    (
        "FMT-C4",
        "sprintf_const",
        _c("""
            /* 良性: sprintf 格式串为常量. */
            #include <stdio.h>

            int main(int argc, char **argv) {
                char out[64];
                sprintf(out, "%d", argc);   /* 常量格式串 */
                printf("%s\\n", out);
                return 0;
            }
        """),
        "sprintf 常量格式串, 仅参数值变化",
    ),
    (
        "FMT-C5",
        "no_args_const",
        _c("""
            /* 良性: 无参常量格式串. */
            #include <stdio.h>

            int main(void) {
                printf("plain message\\n");
                return 0;
            }
        """),
        "无占位符常量格式串",
    ),
    (
        "FMT-C6",
        "helper_const",
        _c("""
            /* 良性: 常量格式串经辅助函数间接传递. */
            #include <stdio.h>

            static void report(const char *fmt, int v) {
                printf(fmt, v);
            }

            int main(int argc, char **argv) {
                report("count: %d\\n", argc);   /* 常量格式串 */
                return 0;
            }
        """),
        "常量格式串经参数传递, 溯源 .rdata",
    ),
    (
        "FMT-C7",
        "snprintf_const",
        _c("""
            /* 良性: snprintf 常量格式串. */
            #include <stdio.h>

            int main(int argc, char **argv) {
                char out[64];
                snprintf(out, sizeof(out), "%s: %d", argv[0], argc);
                printf("%s\\n", out);
                return 0;
            }
        """),
        "snprintf 常量格式串",
    ),
    (
        "FMT-C8",
        "fprintf_const",
        _c("""
            /* 良性: fprintf 常量格式串到 stderr. */
            #include <stdio.h>

            int main(int argc, char **argv) {
                fprintf(stderr, "error code: %d\\n", argc);
                return 0;
            }
        """),
        "fprintf 常量格式串",
    ),
]

ALL_FMT_SAMPLES = FMT_SAMPLES + FMT_CLEAN_SAMPLES


def expected_label(sample_id: str) -> str:
    """按样本 id 返回期望标签: 'vuln' 或 'clean'."""
    for sid, _, _, _ in FMT_SAMPLES:
        if sid == sample_id:
            return 'vuln'
    for sid, _, _, _ in FMT_CLEAN_SAMPLES:
        if sid == sample_id:
            return 'clean'
    raise KeyError(sample_id)


def description(sample_id: str) -> str:
    for sid, _, _, desc in ALL_FMT_SAMPLES:
        if sid == sample_id:
            return desc
    return ''
