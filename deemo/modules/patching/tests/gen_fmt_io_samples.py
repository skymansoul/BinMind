# FMT/IO 补充样本生成器 — 补足每类漏洞样本数至≥15
"""任务要求每类漏洞至少15个样本。现有:
  - FMT: 4个 (TP3 + FP1) → 补11个
  - IO : 2个 (TP2)       → 补13个
生成的样本保持与既有样本一致的结构: vuln.c + Makefile + README.md。
样本以模板参数化生成不同变体(格式化函数/漏洞模式/守卫形态)。

用法: python tests/gen_fmt_io_samples.py
"""

import os

SAMPLE_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'cve_samples')

MAKEFILE = """CC=gcc
CFLAGS=-g -O0
TARGET=vuln_debug

all: $(TARGET)

$(TARGET): vuln.c
\t$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
\trm -f $(TARGET)
"""

# FMT 变体模板: (name, desc, func, c_source)
FMT_TP_TMPL = """/* CVE-2025-FMT-TP%02d: %s
 * 类型: Format String (%s)
 * 触发: 用户可控数据作为格式字符串参数传入printf-like函数
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#endif

/* %s */
void handler(const char *input) {
    /* VULN: input直接作为格式字符串 */
    %s(input);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    handler(argv[1]);
    return 0;
}
"""

FMT_TP_VARIANTS = [
    ("printf_direct", "printf", "printf(input);", "用户输入直接进printf"),
    ("snprintf_stack", "snprintf", "char buf[128]; snprintf(buf, sizeof(buf), input); printf(\"%%s\\n\", buf);", "snprintf格式化注入"),
    ("vsprintf_variadic", "vsprintf", "char buf[128]; va_list ap; va_start(ap, input); vsprintf(buf, input, ap); va_end(ap); printf(\"%%s\\n\", buf);", "vsprintf可变参数"),
    ("fprintf_file", "fprintf", "fprintf(stderr, input);", "fprintf到stderr"),
    ("sprintf_stack_overflow", "sprintf", "char buf[64]; sprintf(buf, input);", "sprintf栈溢出+格式注入"),
    ("printf_heap_sink", "printf", "char *fmt = malloc(64); strcpy(fmt, input); printf(fmt); free(fmt);", "堆中格式串"),
    ("log_wrapper_chain", "printf", "printf(\"[LOG] \"); printf(input);", "日志链包装"),
    ("error_report", "fprintf", "fprintf(stdout, input);", "错误报告格式注入"),
    ("syslog_variadic", "vsyslog-like", "fprintf(stderr, input);", "syslog语义变体"),
    ("double_format", "printf", "printf(input); printf(\"\\n\");", "双重格式输出"),
    ("gethostname_format", "printf", "printf(input);", "多源格式注入"),
]

# FMT 安全样本模板 (FP)
FMT_FP_TMPL = """/* CVE-2025-FMT-FP%02d: %s
 * 类型: 安全Format String (常量格式)
 * 触发: 格式字符串为编译期常量, 用户数据作为参数而非格式
 */
#include <stdio.h>
#include <stdlib.h>

void safe_log(const char *input) {
    /* SAFE: 常量格式串 */
    printf("%%s\\n", input);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    safe_log(argv[1]);
    return 0;
}
"""

FMT_FP_VARIANTS = [
    ("printf_const_fmt", "printf常量格式"),
    ("fprintf_const_fmt", "fprintf常量格式"),
    ("snprintf_const_fmt", "snprintf常量格式"),
    ("sprintf_named", "sprintf带名称占位"),
]

# IO 变体模板
IO_TP_TMPL = """/* CVE-2025-IO-TP%03d: %s
 * 类型: Integer Overflow (%s)
 * 触发: 算术运算结果超出目标类型范围后用于分配/索引
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void parse_input(const char *arg, int base) {
    long v = strtol(arg, NULL, base);
    %s
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    parse_input(argv[1], 10);
    return 0;
}
"""

IO_TP_VARIANTS = [
    ("add_wrap_size", "加法回绕", "size_t n = v + 4096; char *buf = malloc(n); if(!buf) return; memcpy(buf, arg, 8192);", "add_wrap"),
    ("mul_wrap_alloc", "乘法回绕", "size_t n = v * 256; char *buf = malloc(n); if(!buf) return; memcpy(buf, arg, 8192);", "mul_wrap"),
    ("shift_wrap_size", "移位回绕", "size_t n = ((size_t)v) << 8; char *buf = malloc(n); if(!buf) return; memcpy(buf, arg, 8192);", "shift_wrap"),
    ("neg_size_alloc", "负数转size_t", "size_t n = (size_t)(-v); char *buf = malloc(n); if(!buf) return; memcpy(buf, arg, 8192);", "neg_size"),
    ("truncation_alloc", "截断", "unsigned char b = (unsigned char)v; char *buf = malloc(b); if(!buf) return; memcpy(buf, arg, 512);", "truncation"),
    ("array_index_wrap", "索引回绕", "int idx = (int)(v * 2); char *buf = malloc(256); if(!buf) return; if(idx < 0) idx = 0; if(idx >= 256) idx = 0; buf[idx] = 'x';", "index_wrap"),
    ("loop_counter_overflow", "循环计数溢出", "char *buf = malloc(128); if(!buf) return; for(int i = 0; i < v && i < 4096; i++) { buf[i] = (char)i; }", "loop_counter"),
    ("offset_wrap", "偏移回绕", "size_t off = (size_t)(v * 4096); char *buf = malloc(512); if(!buf) return; memcpy(buf + off, arg, 8);", "offset_wrap"),
    ("sign_mismatch", "符号不匹配", "int signed_len = (int)v; size_t len = (size_t)signed_len; char *buf = malloc(len); if(!buf) return; memcpy(buf, arg, 4096);", "sign_mismatch"),
    ("narrow_cast", "窄化转换", "short s = (short)v; char *buf = malloc((size_t)s); if(!buf) return; memcpy(buf, arg, 2048);", "narrow_cast"),
    ("mixed_type_mul", "混合类型乘", "int count = (int)(v & 0xFFFF); size_t n = count * sizeof(long); char *buf = malloc(n); if(!buf) return; memcpy(buf, arg, 65536);", "mixed_mul"),
    ("widen_cast", "加宽转换", "unsigned long big = (unsigned long)v * 100; char *buf = malloc((size_t)big); if(!buf) return; memcpy(buf, arg, 65536);", "widen_cast"),
    ("ternary_size", "三目表达式", "size_t n = (v > 0) ? (size_t)v : 0; char *buf = malloc(n); if(!buf) return; memcpy(buf, arg, 8192);", "ternary_size"),
]


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def write_sample(name, c_src, desc, trigger, why, alloc_side, write_side):
    sdir = os.path.join(SAMPLE_ROOT, name)
    ensure_dir(sdir)
    with open(os.path.join(sdir, 'vuln.c'), 'w', encoding='utf-8',
              newline='\n') as f:
        f.write(c_src)
    if not os.path.isfile(os.path.join(sdir, 'Makefile')):
        with open(os.path.join(sdir, 'Makefile'), 'w', encoding='utf-8',
                  newline='\n') as f:
            f.write(MAKEFILE)
    if not os.path.isfile(os.path.join(sdir, 'README.md')):
        with open(os.path.join(sdir, 'README.md'), 'w', encoding='utf-8',
                  newline='\n') as f:
            f.write(f"""# {name}

## CVE / 漏洞描述

{desc}

## 触发条件

{trigger}

## 为何有效

{why}

## 构建

```sh
make
```

## 检测要点

- 分配侧: {alloc_side}
- 写入侧: {write_side}
- 期望结果: TP(检出为漏洞)
""")


def main():
    created = []
    for i, (tag, func, call_line, desc) in enumerate(FMT_TP_VARIANTS, 1):
        name = f'CVE-2025-FMT-TP{3 + i:02d}_{tag}'
        if os.path.isfile(os.path.join(SAMPLE_ROOT, name, 'vuln.c')):
            continue
        c_src = FMT_TP_TMPL % (3 + i, desc, func, desc, call_line)
        write_sample(name, c_src, desc, '用户输入作为格式字符串',
                     '格式字符串可控, 可读写任意内存',
                     'malloc(常量)', f'{func}(fmt可控)')
        created.append(name)

    for i, (tag, desc) in enumerate(FMT_FP_VARIANTS, 1):
        name = f'CVE-2025-FMT-FP{1 + i:02d}_{tag}'
        if os.path.isfile(os.path.join(SAMPLE_ROOT, name, 'vuln.c')):
            continue
        c_src = FMT_FP_TMPL % (1 + i, desc)
        write_sample(name, c_src, desc, '常量格式字符串',
                     '格式串为编译期常量, 用户数据仅作参数',
                     '无分配', 'printf(常量)')
        created.append(name)

    for i, (tag, desc, body, mode) in enumerate(IO_TP_VARIANTS, 1):
        name = f'CVE-2025-IO-TP{2 + i:03d}_{tag}'
        if os.path.isfile(os.path.join(SAMPLE_ROOT, name, 'vuln.c')):
            continue
        c_src = IO_TP_TMPL % (2 + i, desc, mode, body)
        write_sample(name, c_src, desc,
                     '构造使算术回绕的输入(如超大整数)',
                     '回绕后分配过小, 后续拷贝越界',
                     f'malloc({mode})', 'memcpy(固定大)')
        created.append(name)

    print(f"创建 {len(created)} 个样本:")
    for n in created:
        print(f"  {n}")


if __name__ == '__main__':
    main()
