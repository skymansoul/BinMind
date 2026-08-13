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
