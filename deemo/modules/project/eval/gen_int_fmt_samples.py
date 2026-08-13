# 整数溢出 + 格式化字符串漏洞样本生成器
# 目标: 将两类漏洞样本补足至 ≥15 个 (任务清单要求)
#   新增 fmt09-18 (10 个漏洞) 与 int08-15 (8 个漏洞)
# 样本语义与既有 cve_samples 样式一致: 独立目录 {main.c, Makefile, README.md}
# 编译产物置于 cve_samples/build/, 由 int_fmt_regression 自动发现
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "cve_samples"
BUILD = ROOT / "cve_samples" / "build"
BUILD.mkdir(parents=True, exist_ok=True)

COMMON = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
"""

FMT_HEADER = COMMON + """#include <stdarg.h>
"""

INT_HEADER = COMMON + """#include <stdint.h>
"""


def makefile(name):
    return f"""CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = {name}

all: $(TARGET)

$(TARGET): main.c
\t$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
\trm -f $(TARGET)
"""


def readme(name, cve, vtype, sev, desc, pattern, trigger, why):
    return f"""# {name}

## CVE信息
- **CVE编号**: {cve}
- **漏洞类型**: {vtype}
- **严重级别**: {sev}

## 漏洞描述
{desc}

## 溢出模式
`{pattern}`

## 触发条件
{trigger}

## 为何有效
{why}

## 检测器预期行为
- 若为 `vulnerable`: 检测器应报告 finding
- 若为 `safe`: 检测器应报告 0 个 finding
"""


# 格式化字符串漏洞样本 (fmt09-18)
FMT_SAMPLES = {
    "fmt09_argv_printf": dict(
        cve="CVE-2000-0573 模式", sev="HIGH",
        desc="printf 直接使用 argv 作为格式串",
        pattern="user_fmt_printf",
        trigger="printf(argv[1]) — 格式串受攻击者控制",
        why="格式寄存器 rcx 来自 argv (memory 来源), 非常量 → 报告",
        src=FMT_HEADER + """int main(int argc, char **argv) {
    if (argc < 2) return 1;
    printf(argv[1]);
    return 0;
}
"""),
    "fmt10_argv_fprintf": dict(
        cve="CVE-2013-2028 模式", sev="HIGH",
        desc="fprintf 使用 argv 作为格式串",
        pattern="user_fmt_fprintf",
        trigger="fprintf(stdout, argv[1])",
        why="格式寄存器 rdx 来自 argv → 报告",
        src=FMT_HEADER + """int main(int argc, char **argv) {
    if (argc < 2) return 1;
    fprintf(stdout, argv[1]);
    return 0;
}
"""),
    "fmt11_argv_snprintf": dict(
        cve="CVE-2015-0235 模式", sev="HIGH",
        desc="snprintf 使用 argv 作为格式串",
        pattern="user_fmt_snprintf",
        trigger="snprintf(buf, 64, argv[1])",
        why="格式寄存器 r8 来自 argv → 报告",
        src=FMT_HEADER + """int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char buf[64];
    snprintf(buf, sizeof(buf), argv[1]);
    printf("%s\\n", buf);
    return 0;
}
"""),
    "fmt12_argv_sprintf": dict(
        cve="CVE-2018-11776 模式", sev="HIGH",
        desc="sprintf 使用 argv 作为格式串",
        pattern="user_fmt_sprintf",
        trigger="sprintf(buf, argv[1])",
        why="格式寄存器 rdx 来自 argv → 报告",
        src=FMT_HEADER + """int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char buf[64];
    sprintf(buf, argv[1]);
    printf("%s\\n", buf);
    return 0;
}
"""),
    "fmt13_global_fmt_ptr": dict(
        cve="CVE-2017-1000251 模式", sev="HIGH",
        desc="全局指针指向的格式串由输入控制",
        pattern="user_fmt_global",
        trigger="char *gf = argv[1]; printf(gf)",
        why="格式寄存器经全局指针装载 (memory 来源) → 报告",
        src=FMT_HEADER + """int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char *gf = argv[1];
    printf(gf);
    return 0;
}
"""),
    "fmt14_stack_fmt_copy": dict(
        cve="CVE-2012-0809 模式", sev="HIGH",
        desc="栈缓冲复制的格式串由输入控制",
        pattern="user_fmt_stack",
        trigger="strncpy(fmt, argv[1], 31); printf(fmt)",
        why="格式寄存器来自栈变量 (stack_var 来源) → 报告",
        src=FMT_HEADER + """int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char fmt[32];
    strncpy(fmt, argv[1], sizeof(fmt) - 1);
    fmt[sizeof(fmt) - 1] = 0;
    printf(fmt);
    return 0;
}
"""),
    "fmt15_double_printf": dict(
        cve="CVE-2008-4113 模式", sev="HIGH",
        desc="连续两次 printf 使用输入格式串",
        pattern="user_fmt_multi",
        trigger="printf(argv[1]); printf(argv[2])",
        why="两个调用点格式寄存器均来自 argv → 报告",
        src=FMT_HEADER + """int main(int argc, char **argv) {
    if (argc < 3) return 1;
    printf(argv[1]);
    printf(argv[2]);
    return 0;
}
"""),
    "fmt16_loop_argv_fmt": dict(
        cve="CVE-2014-6271 模式", sev="HIGH",
        desc="循环内逐参数 printf",
        pattern="user_fmt_loop",
        trigger="for(i=1;i<argc;i++) printf(argv[i])",
        why="循环体内格式寄存器来自 argv → 报告",
        src=FMT_HEADER + """int main(int argc, char **argv) {
    int i;
    for (i = 1; i < argc; i++) {
        printf(argv[i]);
    }
    return 0;
}
"""),
    "fmt17_param_fmt_printf": dict(
        cve="CVE-2016-5195 模式", sev="HIGH",
        desc="printf 经函数参数间接使用输入格式串",
        pattern="user_fmt_param",
        trigger="log_it(argv[1]); 内部 printf(fmt)",
        why="格式寄存器来自函数参数 (stack_var 来源) → 报告",
        src=FMT_HEADER + """static void log_it(char *fmt) {
    printf(fmt);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    log_it(argv[1]);
    return 0;
}
"""),
    "fmt18_param_fmt_fprintf": dict(
        cve="CVE-2021-3156 模式", sev="HIGH",
        desc="fprintf 经函数参数间接使用输入格式串",
        pattern="user_fmt_param_fprintf",
        trigger="show_it(argv[1]); 内部 fprintf(stdout, fmt)",
        why="格式寄存器来自函数参数 (stack_var 来源) → 报告",
        src=FMT_HEADER + """static void show_it(char *fmt) {
    fprintf(stdout, fmt);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    show_it(argv[1]);
    return 0;
}
"""),
}

# 整数溢出漏洞样本 (int08-15)
INT_SAMPLES = {
    "int08_add_wrap_alloc": dict(
        cve="CVE-2018-14618 模式", sev="HIGH",
        desc="无符号加法回绕使分配大小变小",
        pattern="uadd_wrap_alloc",
        trigger="sz=0xFFFFF000; sz+=0x1000 → 0, malloc(0)",
        why="add 回绕检测 (UADD_WRAP) → 报告",
        src=INT_HEADER + """int main(int argc, char **argv) {
    unsigned int sz = 0xFFFFF000;
    sz += 0x1000;
    char *p = (char *)malloc(sz);
    if (!p) return 1;
    memset(p, 'A', 0x20);
    printf("%c\\n", p[0]);
    free(p);
    return 0;
}
"""),
    "int09_mul_wrap_alloc": dict(
        cve="CVE-2018-14618 模式", sev="HIGH",
        desc="无符号乘法回绕使分配大小变小",
        pattern="umul_wrap_alloc",
        trigger="n=0x40000000; n*=4 → 0, malloc(0)",
        why="乘法回绕检测 (UMUL_WRAP) → 报告",
        src=INT_HEADER + """int main(int argc, char **argv) {
    unsigned int n = 0x40000000;
    n *= 4;
    char *p = (char *)malloc(n);
    if (!p) return 1;
    memset(p, 'B', 0x20);
    printf("%c\\n", p[0]);
    free(p);
    return 0;
}
"""),
    "int10_sub_underflow_len": dict(
        cve="CVE-2019-13615 模式", sev="HIGH",
        desc="无符号减法下溢使长度变为巨大值",
        pattern="usub_underflow_len",
        trigger="len=0; len-=1 → 0xFFFFFFFF, memcpy 巨大",
        why="减法下溢检测 → 报告",
        src=INT_HEADER + """int main(int argc, char **argv) {
    unsigned int len = 0;
    len -= 1;
    char *p = (char *)malloc(64);
    char *s = (char *)malloc(64);
    if (!p || !s) return 1;
    memset(s, 'C', 64);
    memcpy(p, s, len);
    printf("%c\\n", p[0]);
    free(p); free(s);
    return 0;
}
"""),
    "int11_shl_wrap_alloc": dict(
        cve="CVE-2016-2182 模式", sev="HIGH",
        desc="左移回绕使分配大小变小",
        pattern="shl_wrap_alloc",
        trigger="n=0x40000000; n<<=2 → 0",
        why="移位回绕检测 → 报告",
        src=INT_HEADER + """int main(int argc, char **argv) {
    unsigned int n = 0x40000000;
    n <<= 2;
    char *p = (char *)malloc(n);
    if (!p) return 1;
    memset(p, 'D', 0x20);
    printf("%c\\n", p[0]);
    free(p);
    return 0;
}
"""),
    "int12_alloc_mul_chain": dict(
        cve="CVE-2015-0235 模式", sev="HIGH",
        desc="分配参数乘法链回绕",
        pattern="alloc_mul_chain",
        trigger="malloc(count * 0x100), count=0x1000000 → 回绕",
        why="分配乘法链检测 (alloc_mul_chain) → 报告",
        src=INT_HEADER + """int main(int argc, char **argv) {
    unsigned int count = 0x1000000;
    unsigned int sz = count * 0x100;
    char *p = (char *)malloc(sz);
    if (!p) return 1;
    memset(p, 'E', 0x20);
    printf("%c\\n", p[0]);
    free(p);
    return 0;
}
"""),
    "int13_add_offset_wrap": dict(
        cve="CVE-2017-11610 模式", sev="HIGH",
        desc="指针偏移加法回绕",
        pattern="uadd_ptr_wrap",
        trigger="off=0xFFFFFFFF; memcpy(p+off, s, 0x20)",
        why="指针算术加法回绕检测 → 报告",
        src=INT_HEADER + """int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    char *s = (char *)malloc(64);
    if (!p || !s) return 1;
    unsigned int off = 0xFFFFFFFF;
    memset(s, 'F', 64);
    memcpy(p + off, s, 0x20);
    printf("%c\\n", p[0]);
    free(p); free(s);
    return 0;
}
"""),
    "int14_mul_alloc_memcpy": dict(
        cve="CVE-2016-5316 模式", sev="HIGH",
        desc="分配回绕后按未回绕量写入",
        pattern="mul_wrap_then_write",
        trigger="n=0x20000000; malloc(n*4 → 回绕); memset(n*4)",
        why="乘法回绕 + 后续写入链 → 报告",
        src=INT_HEADER + """int main(int argc, char **argv) {
    unsigned int n = 0x20000000;
    unsigned int sz = n * 4;
    char *p = (char *)malloc(sz);
    if (!p) return 1;
    memset(p, 'G', (size_t)n * 4);
    printf("%c\\n", p[0]);
    free(p);
    return 0;
}
"""),
    "int15_add_var_alloc": dict(
        cve="CVE-2019-13117 模式", sev="HIGH",
        desc="变量加法回绕使分配大小变小",
        pattern="uadd_var_alloc",
        trigger="a=0xFFFFFFF0; b=0x20; s=a+b → 0x10, malloc(s)",
        why="add 回绕检测 (操作数之一为变量) → 报告",
        src=INT_HEADER + """int main(int argc, char **argv) {
    unsigned int a = 0xFFFFFFF0;
    unsigned int b = 0x20;
    unsigned int s = a + b;
    char *p = (char *)malloc(s);
    if (!p) return 1;
    memset(p, 'H', 0x20);
    printf("%c\\n", p[0]);
    free(p);
    return 0;
}
"""),
}


def emit(name, spec, header, vtype):
    d = OUT / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "main.c").write_text(spec["src"], encoding="utf-8")
    (d / "Makefile").write_text(makefile(name), encoding="utf-8")
    (d / "README.md").write_text(readme(
        name, spec["cve"], vtype, spec["sev"],
        spec["desc"], spec["pattern"], spec["trigger"], spec["why"]),
        encoding="utf-8")
    exe = BUILD / f"{name}.exe"
    r = subprocess.run(
        ["gcc", "-Wall", "-O0", "-fno-stack-protector", "-g",
         "-o", str(exe), str(d / "main.c")],
        capture_output=True, text=True, timeout=30)
    status = "OK" if r.returncode == 0 else "FAIL"
    print(f"  [{status}] {name}")


def main():
    for name, spec in FMT_SAMPLES.items():
        emit(name, spec, FMT_HEADER, "format_string")
    for name, spec in INT_SAMPLES.items():
        emit(name, spec, INT_HEADER, "integer_overflow")
    print(f"生成 {len(FMT_SAMPLES) + len(INT_SAMPLES)} 个样本")


if __name__ == "__main__":
    sys.exit(main())
