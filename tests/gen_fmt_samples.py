"""生成15个格式串漏洞测试样本。"""
import os

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'samples', 'format_string')

SAMPLES = {
'fmt_direct_user': r'''#include <stdio.h>
#include <stdlib.h>
/* FMT-01: 用户输入直接作为格式串 — 经典fmt漏洞 */
int main(int argc, char **argv) {
    if (argc < 2) { printf("Usage: %s <fmt>\n", argv[0]); return 1; }
    printf(argv[1]);  /* VULNERABLE: 用户控制格式串 */
    return 0;
}
''',
'fmt_constant_safe': r'''#include <stdio.h>
/* FMT-02: 常量格式串 — 安全, 不应报告 */
int main(void) {
    printf("hello %s %d\n", "world", 42);  /* SAFE: 编译时常量 */
    return 0;
}
''',
'fmt_stack_leak': r'''#include <stdio.h>
#include <stdlib.h>
/* FMT-03: 通过%x/%p泄露栈数据 */
int main(int argc, char **argv) {
    char buf[64];
    if (argc > 1) snprintf(buf, sizeof(buf), argv[1]);  /* VULNERABLE */
    else snprintf(buf, sizeof(buf), "safe: %%s");
    printf("%s\n", buf);
    return 0;
}
''',
'fmt_n_write': r'''#include <stdio.h>
#include <string.h>
/* FMT-04: 用户输入含%n — 任意地址写原语 */
int main(int argc, char **argv) {
    int written = 0;
    char fmt[128];
    if (argc > 1) {
        strncpy(fmt, argv[1], sizeof(fmt)-1);
        fmt[127] = '\0';
    } else {
        strcpy(fmt, "hello %n");
    }
    printf(fmt, &written);  /* VULNERABLE: fmt可能含%n */
    printf("written=%d\n", written);
    return 0;
}
''',
'fmt_positional': r'''#include <stdio.h>
/* FMT-05: 位置参数 — %n$ 可以跳过参数到达任意栈位置 */
int main(int argc, char **argv) {
    int a=1, b=2, c=3, d=4, e=5, f=6, g=7, h=8;
    if (argc > 1)
        printf(argv[1], a,b,c,d,e,f,g,h);  /* VULNERABLE: %8$x泄露第8个参数 */
    return 0;
}
''',
'fmt_width_leak': r'''#include <stdio.h>
#include <string.h>
/* FMT-06: %*d 宽度参数泄露 — 用户控制宽度可泄露栈上更多数据 */
int main(int argc, char **argv) {
    char input[256];
    if (argc > 1) {
        strncpy(input, argv[1], 255);
        printf(input, 42);  /* VULNERABLE: %*d 宽度由用户控制 */
    } else {
        printf("safe: value=%d\n", 42);
    }
    return 0;
}
''',
'fmt_heap_fmt': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* FMT-07: 堆上的格式串 — 格式串存储在堆而非栈 */
int main(int argc, char **argv) {
    char *fmt = (char *)malloc(256);
    if (!fmt) return 1;
    if (argc > 1) strcpy(fmt, argv[1]);
    else strcpy(fmt, "heap fmt: %s");
    printf(fmt, "test");  /* VULNERABLE if argc>1 */
    free(fmt);
    return 0;
}
''',
'fmt_indirect_fmt': r'''#include <stdio.h>
#include <stdlib.h>
/* FMT-08: 间接格式串 — 格式串来自全局变量/配置文件 */
static const char *g_fmt = NULL;
void load_config(void) { g_fmt = "config: %s\n"; }
void load_user(const char *s) { g_fmt = s; }

int main(int argc, char **argv) {
    if (argc > 1) load_user(argv[1]);
    else load_config();
    printf(g_fmt, "value");  /* VULNERABLE if argc>1 */
    return 0;
}
''',
'fmt_snprintf_safe': r'''#include <stdio.h>
#include <stdlib.h>
/* FMT-09: snprintf 带固定格式串 — 安全, 不应报告 */
int main(int argc, char **argv) {
    char buf[256];
    if (argc > 1)
        snprintf(buf, sizeof(buf), "user_input: %s", argv[1]);  /* SAFE */
    else
        snprintf(buf, sizeof(buf), "no input");
    printf("%s\n", buf);
    return 0;
}
''',
'fmt_vprintf_wrap': r'''#include <stdio.h>
#include <stdarg.h>
#include <string.h>
/* FMT-10: vprintf包装 — 如果包装函数接收用户格式串则危险 */
void log_msg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);  /* 如果fmt来自用户 → VULNERABLE */
    va_end(ap);
}
int main(int argc, char **argv) {
    const char *fmt = argc > 1 ? argv[1] : "safe: %d\n";
    log_msg(fmt, 42);
    return 0;
}
''',
}

MAKEFILE = 'CC=gcc\nCFLAGS=-g -O0 -fno-stack-protector\n\nall: vuln\n\nvuln: vuln.c\n\t$ $(CFLAGS) -o vuln vuln.c\n\nclean:\n\trm -f vuln\n'

for name, code in SAMPLES.items():
    d = os.path.join(BASE, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'vuln.c'), 'w') as f: f.write(code)
    with open(os.path.join(d, 'Makefile'), 'w') as f: f.write(MAKEFILE)
    with open(os.path.join(d, 'README.md'), 'w') as f:
        f.write(f'# {name}\n**CWE-134** — Format String Vulnerability\n\n')
        f.write(f'## Detection Goal\nBinMind FSCS (Format String Constraint System) ')
        f.write(f'should detect user-controlled format strings with %n write primitive.\n')
    print(f'  OK: {name}')

print(f'Done: {len(SAMPLES)} format_string samples')
