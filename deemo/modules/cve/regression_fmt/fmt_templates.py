# 格式化字符串样本模板 — C 源码 / Makefile / README 的生成模板.
#
# 模板按 pattern 选型; 漏洞模板覆盖 argv/全局/输入缓冲三类格式串来源,
# 安全模板覆盖栈槽常量/只读字面量/直接字面量三类误报挑战.
#
# 创建: 2025-01-13

_VULN_TEMPLATES = {
    "argv_fmt": """/* {cve} {desc}. */
#include <stdio.h>

int main(int argc, char **argv) {{
    if (argc < 2) return 1;
    printf(argv[1]);
    return 0;
}}
""",
    "fprintf_argv": """/* {cve} {desc}. */
#include <stdio.h>

int main(int argc, char **argv) {{
    if (argc < 2) return 1;
    fprintf(stderr, argv[1]);
    return 0;
}}
""",
    "snprintf_fmt": """/* {cve} {desc}. */
#include <stdio.h>

int main(int argc, char **argv) {{
    char dst[128];
    if (argc < 2) return 1;
    snprintf(dst, sizeof(dst), argv[1]);
    puts(dst);
    return 0;
}}
""",
    "global_fmt": """/* {cve} {desc}. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {{
    char fmt[256];
    if (argc < 2) return 1;
    strcpy(fmt, argv[1]);
    printf(fmt);
    return 0;
}}
""",
    "gets_fmt": """/* {cve} {desc}. */
#include <stdio.h>

int main(int argc, char **argv) {{
    char g[256];
    if (!gets(g)) return 1;
    printf(g);
    return 0;
}}
""",
}

_SAFE_TEMPLATES = {
    "stack_const": """/* {cve} 安全对照: 栈槽常量初始化, 非用户可控. */
#include <stdio.h>

int main(int argc, char **argv) {{
    char fmt[] = "val=%d\\n";
    printf(fmt, argc);
    return 0;
}}
""",
    "ptr_literal": """/* {cve} 安全对照: 指针指向 .rdata 字面量, 非用户可控. */
#include <stdio.h>

int main(int argc, char **argv) {{
    const char *fmt = "%d\\n";
    printf(fmt, argc);
    return 0;
}}
""",
    "direct_literal": """/* {cve} 安全对照: 直接字面量格式串. */
#include <stdio.h>

int main(int argc, char **argv) {{
    printf("%s\\n", argc > 1 ? argv[1] : "none");
    return 0;
}}
""",
    "global_literal": """/* {cve} 安全对照: 全局只读字面量格式串. */
#include <stdio.h>

static const char g_fmt[] = "%d\\n";

int main(int argc, char **argv) {{
    printf(g_fmt, argc);
    return 0;
}}
""",
    "snprintf_literal": """/* {cve} 安全对照: snprintf 有界字面量格式串. */
#include <stdio.h>

int main(int argc, char **argv) {{
    char dst[64];
    snprintf(dst, sizeof(dst), "%s", argc > 1 ? argv[1] : "none");
    puts(dst);
    return 0;
}}
""",
}

MAKEFILE = """# {sample} 编译入口.
# Windows (mingw) 产出 vuln.exe (PE), Linux 产出 vuln (ELF).
CC ?= gcc
CFLAGS ?= -O0 -Wall

EXE = vuln$(if $(filter Windows_NT,$(OS)),.exe,)

all: $(EXE)

$(EXE): vuln.c
	$(CC) $(CFLAGS) vuln.c -o $@

O2: vuln.c
	$(CC) -O2 -Wall vuln.c -o vuln_O2$(if $(filter Windows_NT,$(OS)),.exe,)

clean:
	-rm -f vuln vuln.exe vuln_O2 vuln_O2.exe

.PHONY: all O2 clean
"""

README = """# {sample}

- CVE: {cve}
- 类型: {type}
- 模式: {pattern}
- Ground truth: 预期 {expected}

## 漏洞描述

{desc}

## 触发条件

{vuln} 代码将 {trigger} 作为 printf 族格式字符串使用,
构成格式化字符串漏洞 (CWE-134).

## 为何该样本可验证检测器有效性

- 格式串来源可从反汇编回溯 (字面量/栈槽/argv/输入函数).
- 期望 {expected} 判定: 检测器应在不丢失召回的前提下
  区分用户可控格式串与栈槽/只读字面量初始化格式串.
"""

TRIGGERS = {
    "argv_fmt": "argv 参数",
    "fprintf_argv": "argv 参数",
    "snprintf_fmt": "argv 参数",
    "global_fmt": "全局缓冲 (复制自 argv)",
    "gets_fmt": "gets 输入",
    "stack_const": "栈槽常量",
    "ptr_literal": ".rdata 字面量指针",
    "direct_literal": "直接字面量",
    "global_literal": "全局只读字面量",
    "snprintf_literal": "snprintf 字面量",
}


def select_template(pattern: str, is_vuln: bool):
    if not is_vuln:
        return _SAFE_TEMPLATES[pattern]
    return _VULN_TEMPLATES[pattern]
