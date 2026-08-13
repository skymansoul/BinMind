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
