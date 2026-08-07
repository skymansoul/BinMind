#!/usr/bin/env python
# coding: utf-8
# tests/fmt_fp_benchmark/gen_samples.py — 格式串误报基准样本生成器
# 15 个漏洞样本 (tp_*) + 15 个安全对照 (tn_*)。每个样本: vuln.c + Makefile
# + README.md + truth.json。运行: python gen_samples.py [--out 输出目录]

import json
from pathlib import Path


TP = [
    dict(id="tp_01_argv_format", label="tp", cwe="CWE-134",
         cve="CVE-2018-14665 类直接 argv 格式串",
         title="printf(argv[1])", trigger="./sample '%n%n%n'",
         why="格式串完全由攻击者控制",
         expect_overflow=True,
         code='''
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc > 1) { printf(argv[1]); }
    return 0;
}
'''),
    dict(id="tp_02_tainted_recv_buffer", label="tp", cwe="CWE-134",
         cve="CVE-2015-8612 类网络输入格式串",
         title="recv 缓冲区直接 printf", trigger="网络输入注入 %s",
         why="buf 内容来自网络, printf(buf) 将其当格式串",
         expect_overflow=True,
         code='''
#include <stdio.h>
int main(void) {
    char buf[64];
    recv(0, buf, sizeof(buf), 0);
    printf(buf);
    return 0;
}
'''),
    dict(id="tp_03_syslog_tainted", label="tp", cwe="CWE-134",
         cve="CVE-2016-10158 类 syslog 格式串",
         title="syslog 用户输入", trigger="输入含 %n",
         why="syslog 首个非固定参数被当格式串",
         expect_overflow=True,
         code='''
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc > 1) { syslog(0, argv[1]); }
    return 0;
}
'''),
    dict(id="tp_04_fgets_printf", label="tp", cwe="CWE-134",
         cve="CVE-2017-1000369 类 fgets 格式串",
         title="fgets 读入后 printf", trigger="stdin 输入 %n",
         why="stdin 内容当格式串解析",
         expect_overflow=True,
         code='''
#include <stdio.h>
int main(void) {
    char buf[128];
    if (fgets(buf, sizeof(buf), stdin)) { printf(buf); }
    return 0;
}
'''),
    dict(id="tp_05_sprintf_tainted_fmt", label="tp", cwe="CWE-134",
         cve="CVE-2020-25656 类 sprintf 污点格式",
         title="sprintf 用攻击者格式串", trigger="argv 注入 %n",
         why="fmt 来自 argv 且作为 sprintf 格式参数",
         expect_overflow=True,
         code='''
#include <stdio.h>
int main(int argc, char **argv) {
    char out[256];
    if (argc > 1) { sprintf(out, argv[1], 1); }
    return 0;
}
'''),
    dict(id="tp_06_arg_chain", label="tp", cwe="CWE-134",
         cve="CVE-2019-12817 类参数链格式串",
         title="经函数参数传递的格式串", trigger="argv 注入",
         why="user 经两层传递到达 printf 格式位置",
         expect_overflow=True,
         code='''
#include <stdio.h>
static void emit(const char *fmt) { printf(fmt); }
int main(int argc, char **argv) {
    if (argc > 1) { emit(argv[1]); }
    return 0;
}
'''),
    dict(id="tp_07_getenv_format", label="tp", cwe="CWE-134",
         cve="CVE-2017-1000371 类环境变量格式串",
         title="getenv 结果当格式串", trigger="设置 HOME=%x",
         why="环境变量内容被当格式串",
         expect_overflow=True,
         code='''
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *h = getenv("HOME");
    if (h) { printf(h); }
    return 0;
}
'''),
    dict(id="tp_08_scanf_printf", label="tp", cwe="CWE-134",
         cve="CVE-2015-0235 类 scanf 格式串",
         title="scanf 读入后 printf", trigger="stdin 输入 %n",
         why="scanf %s 读入后当格式串",
         expect_overflow=True,
         code='''
#include <stdio.h>
int main(void) {
    char buf[128];
    scanf("%s", buf);
    printf(buf);
    return 0;
}
'''),
    dict(id="tp_09_percent_n_write", label="tp", cwe="CWE-134",
         cve="CVE-2012-0809 类 %n 写原语",
         title="攻击者格式串含 %n", trigger="输入 %n%n%n",
         why="%n 可写任意内存地址",
         expect_overflow=True,
         code='''
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc > 1) { printf(argv[1]); }
    return 0;
}
'''),
    dict(id="tp_10_vprintf_tainted", label="tp", cwe="CWE-134",
         cve="CVE-2021-3156 类 vprintf 格式串",
         title="vprintf 攻击者格式", trigger="argv 注入 %s",
         why="fmt 由攻击者控制传入 vprintf",
         expect_overflow=True,
         code='''
#include <stdio.h>
#include <stdarg.h>
static void do_log(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}
int main(int argc, char **argv) {
    if (argc > 1) { do_log(argv[1]); }
    return 0;
}
'''),
    dict(id="tp_11_fprintf_tainted", label="tp", cwe="CWE-134",
         cve="CVE-2020-10757 类 fprintf 格式串",
         title="fprintf 攻击者格式到 stderr", trigger="argv 注入",
         why="用户输入直接作为 fprintf 格式",
         expect_overflow=True,
         code='''
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc > 1) { fprintf(stderr, argv[1]); }
    return 0;
}
'''),
    dict(id="tp_12_strcpy_tainted_fmt", label="tp", cwe="CWE-134",
         cve="CVE-2016-6301 类复制后格式串",
         title="strcpy 拷贝 argv 后 printf", trigger="argv 注入 %n",
         why="fmt 被拷贝进栈缓冲后仍当格式串",
         expect_overflow=True,
         code='''
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char fmt[256];
    if (argc > 1) {
        strcpy(fmt, argv[1]);
        printf(fmt);
    }
    return 0;
}
'''),
    dict(id="tp_13_snprintf_tainted_fmt", label="tp", cwe="CWE-134",
         cve="CVE-2018-14634 类 snprintf 格式串",
         title="snprintf 攻击者格式", trigger="argv 注入 %x",
         why="snprintf 格式参数仍来自用户",
         expect_overflow=True,
         code='''
#include <stdio.h>
int main(int argc, char **argv) {
    char out[256];
    if (argc > 1) { snprintf(out, sizeof(out), argv[1]); }
    return 0;
}
'''),
    dict(id="tp_14_conditional_tainted", label="tp", cwe="CWE-134",
         cve="CVE-2019-19043 类条件格式串",
         title="条件分支内 printf 攻击者格式", trigger="./sample 1",
         why="flag=1 时用户格式串被解析",
         expect_overflow=True,
         code='''
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    int flag = argc > 1 ? atoi(argv[1]) : 0;
    if (flag && argc > 2) { printf(argv[2]); }
    return 0;
}
'''),
    dict(id="tp_15_log_custom_fmt", label="tp", cwe="CWE-134",
         cve="CVE-2022-1015 类自定义日志格式串",
         title="日志系统把用户串当格式", trigger="输入 %p",
         why="log_msg 直接 printf 用户串",
         expect_overflow=True,
         code='''
#include <stdio.h>
static void log_msg(const char *m) { printf(m); }
int main(int argc, char **argv) {
    if (argc > 1) { log_msg(argv[1]); }
    return 0;
}
'''),
]

TN = [
    dict(id="tn_01_literal_format", label="tn", cwe="CWE-0",
         cve="安全模式: 字面量格式串",
         title="printf(\"hello %s\")", trigger="直接执行 main",
         why="格式串是编译期常量, 攻击者不可控",
         expect_overflow=False,
         code='''
#include <stdio.h>
int main(int argc, char **argv) {
    const char *name = argc > 1 ? argv[1] : "world";
    printf("hello %s\\n", name);
    return 0;
}
'''),
    dict(id="tn_02_internal_const_copy", label="tn", cwe="CWE-0",
         cve="安全模式: 内部常量拷贝",
         title="strcpy 常量后 printf", trigger="直接执行 main",
         why="fmt 被解析为常量字面量, 无 %n",
         expect_overflow=False,
         code='''
#include <stdio.h>
#include <string.h>
int main(void) {
    char fmt[64];
    strcpy(fmt, "value=%d\\n");
    printf(fmt, 42);
    return 0;
}
'''),
    dict(id="tn_03_assigned_literal", label="tn", cwe="CWE-0",
         cve="安全模式: 变量赋字面量",
         title="char* f = 常量; printf(f)", trigger="直接执行 main",
         why="f 指向常量字符串",
         expect_overflow=False,
         code='''
#include <stdio.h>
int main(void) {
    char *f = "fixed output\\n";
    printf(f);
    return 0;
}
'''),
    dict(id="tn_04_snprintf_output", label="tn", cwe="CWE-0",
         cve="安全模式: snprintf 输出再打印",
         title="snprintf 生成常量格式输出", trigger="直接执行 main",
         why="buf 内容为常量格式的输出, 不含用户控制格式串",
         expect_overflow=False,
         code='''
#include <stdio.h>
int main(void) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%d-%d", 1, 2);
    printf("%s", buf);
    return 0;
}
'''),
    dict(id="tn_05_escaped_percent", label="tn", cwe="CWE-0",
         cve="安全模式: 转义百分号",
         title="printf(\"100%%\")", trigger="直接执行 main",
         why="%% 是转义, 不构成控制符",
         expect_overflow=False,
         code='''
#include <stdio.h>
int main(void) {
    printf("100%% complete\\n");
    return 0;
}
'''),
    dict(id="tn_06_argv_as_data", label="tn", cwe="CWE-0",
         cve="安全模式: argv 仅作数据参数",
         title="printf(\"%s\", argv[1])", trigger="任意 argv",
         why="格式串为常量, argv 只是 %s 的数据",
         expect_overflow=False,
         code='''
#include <stdio.h>
int main(int argc, char **argv) {
    printf("arg=%s\\n", argc > 1 ? argv[1] : "none");
    return 0;
}
'''),
    dict(id="tn_07_const_variable_name", label="tn", cwe="CWE-0",
         cve="安全模式: 名为 fmt 的常量",
         title="char fmt[]=\"ok\"; printf(fmt)", trigger="直接执行 main",
         why="fmt 变量内容为常量",
         expect_overflow=False,
         code='''
#include <stdio.h>
int main(void) {
    char fmt[] = "ok\\n";
    printf(fmt);
    return 0;
}
'''),
    dict(id="tn_08_snprintf_literal", label="tn", cwe="CWE-0",
         cve="安全模式: snprintf 字面量格式",
         title="snprintf(dst, n, \"%s\", data)", trigger="直接执行 main",
         why="格式串字面量, 数据作为参数",
         expect_overflow=False,
         code='''
#include <stdio.h>
int main(int argc, char **argv) {
    char out[128];
    snprintf(out, sizeof(out), "%s", argc > 1 ? argv[1] : "x");
    return 0;
}
'''),
    dict(id="tn_09_positional_literal", label="tn", cwe="CWE-0",
         cve="安全模式: 位置参数常量格式",
         title="printf(\"%1$s\", argv[1])", trigger="任意 argv",
         why="格式串仍为常量",
         expect_overflow=False,
         code='''
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc > 1) { printf("%1$s\\n", argv[1]); }
    return 0;
}
'''),
    dict(id="tn_10_syslog_const", label="tn", cwe="CWE-0",
         cve="安全模式: syslog 常量格式",
         title="syslog(LOG_INFO, \"fixed %s\", data)", trigger="直接执行 main",
         why="syslog 格式串为常量, 数据经 %s 传入",
         expect_overflow=False,
         code='''
#include <stdio.h>
int main(void) {
    syslog(0, "fixed message");
    return 0;
}
'''),
    dict(id="tn_11_fprintf_literal", label="tn", cwe="CWE-0",
         cve="安全模式: fprintf 常量格式",
         title="fprintf(stderr, \"%s\", argv[1])", trigger="任意 argv",
         why="fprintf 格式串常量",
         expect_overflow=False,
         code='''
#include <stdio.h>
int main(int argc, char **argv) {
    fprintf(stderr, "err=%s\\n", argc > 1 ? argv[1] : "?");
    return 0;
}
'''),
    dict(id="tn_12_conditional_literal", label="tn", cwe="CWE-0",
         cve="安全模式: 分支字面量格式",
         title="if(flag) printf(\"a\") else printf(\"b\")", trigger="任意 flag",
         why="两个分支均为常量格式串",
         expect_overflow=False,
         code='''
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    int flag = argc > 1 ? atoi(argv[1]) : 0;
    if (flag) { printf("yes\\n"); } else { printf("no\\n"); }
    return 0;
}
'''),
    dict(id="tn_13_const_tag", label="tn", cwe="CWE-0",
         cve="安全模式: 常量标签打印",
         title="char tag[]=\"INFO\"; printf(tag)", trigger="直接执行 main",
         why="tag 内容为常量",
         expect_overflow=False,
         code='''
#include <stdio.h>
int main(void) {
    char tag[] = "INFO";
    printf(tag);
    return 0;
}
'''),
    dict(id="tn_14_printf_percent_s_only", label="tn", cwe="CWE-0",
         cve="安全模式: 仅数据格式化",
         title="printf(\"%s %d\", data, n)", trigger="任意 data",
         why="格式串为常量字面量",
         expect_overflow=False,
         code='''
#include <stdio.h>
int main(int argc, char **argv) {
    printf("v=%s n=%d\\n", argc > 1 ? argv[1] : "", 0);
    return 0;
}
'''),
    dict(id="tn_15_internal_safe_log", label="tn", cwe="CWE-0",
         cve="安全模式: 内部安全日志",
         title="内部日志 printf 固定格式", trigger="直接执行 main",
         why="所有 printf 均为字面量或常量变量",
         expect_overflow=False,
         code='''
#include <stdio.h>
static const char *kMsg = "state: %d\\n";
int main(void) {
    printf(kMsg, 3);
    printf("done\\n");
    return 0;
}
'''),
]

MAKEFILE = ("CC = gcc\nCFLAGS = -Wall -Wextra -O0 -g\nTARGET = sample\n"
            "all: $(TARGET)\n$(TARGET): vuln.c\n\t$(CC) $(CFLAGS) -o "
            "$(TARGET) vuln.c\nclean:\n\t$(RM) $(TARGET)\n")

README_TEMPLATE = ("# {sid}: {title}\n\n## CWE\n{cwe}\n\n## 漏洞描述\n{cve}"
                   "\n\n## 触发条件\n{trigger}\n\n## 为何有效\n{why}\n\n"
                   "## Build\n```bash\nmake\n./sample\n```\n")


def _write(out: Path, spec: dict):
    d = out / spec["id"]
    d.mkdir(parents=True, exist_ok=True)
    header = ("/* FMT TP sample */\n" if spec["label"] == "tp"
              else "/* FMT TN (safe) sample */\n")
    (d / "vuln.c").write_text(header + spec["code"].strip() + "\n",
                              encoding="utf-8")
    (d / "Makefile").write_text(MAKEFILE, encoding="utf-8")
    (d / "README.md").write_text(README_TEMPLATE.format(sid=spec["id"], **spec),
                                 encoding="utf-8")
    truth = {"sample_id": spec["id"], "label": spec["label"],
             "cwe": spec["cwe"], "cve": spec["cve"],
             "expect_overflow": spec["expect_overflow"],
             "trigger": spec["trigger"], "why": spec["why"]}
    (d / "truth.json").write_text(json.dumps(truth, indent=2,
                                             ensure_ascii=False),
                                  encoding="utf-8")





def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(Path(__file__).parent))
    args = parser.parse_args()
    out = Path(args.out)
    for spec in TP + TN:
        _write(out, spec)
    print(f"Generated {len(TP) + len(TN)} FMT samples in {out}")


if __name__ == "__main__":
    main()
