# UAF 样本模板 - C 源码 / Makefile / README 的生成模板.
#
# 模板按 pattern 选型; 漏洞模板覆盖 free->use 的直接使用形态,
# 安全模板覆盖指针复活/置空/路径互斥/cleanup 四类误报挑战.
#

_VULN_TEMPLATES = {
    "printf_use": """/* {cve} {desc}. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {{
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    printf("%s\\n", p);
    return 0;
}}
""",
    "strlen_use": """/* {cve} {desc}. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {{
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    size_t n = strlen(p);
    printf("len=%zu\\n", n);
    return 0;
}}
""",
    "memcpy_use": """/* {cve} {desc}. */
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {{
    char *p = (char *)malloc(64);
    char dst[64];
    if (!p) return 1;
    free(p);
    memcpy(dst, p, 16);
    return 0;
}}
""",
    "memset_use": """/* {cve} {desc}. */
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {{
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    memset(p, 0, 16);
    return 0;
}}
""",
    "write_deref": """/* {cve} {desc}. */
#include <stdlib.h>

int main(int argc, char **argv) {{
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    p[0] = 'A';
    return 0;
}}
""",
}

_SAFE_TEMPLATES = {
    "reborn_call": """/* {cve} 安全对照: 指针经函数返回值复活, 非 UAF. */
#include <stdio.h>
#include <stdlib.h>

static char *get_ptr(void) {{
    return (char *)malloc(32);
}}

int main(int argc, char **argv) {{
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    p = get_ptr();
    printf("%s\\n", p);
    free(p);
    return 0;
}}
""",
    "reborn_malloc": """/* {cve} 安全对照: 指针经重新 malloc 复活, 非 UAF. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {{
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    p = (char *)malloc(64);
    printf("%s\\n", p);
    free(p);
    return 0;
}}
""",
    "nulled_guard": """/* {cve} 安全对照: free 后置空并在守卫内使用, 非 UAF. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {{
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    p = NULL;
    if (p) printf("%s\\n", p);
    return 0;
}}
""",
    "error_path": """/* {cve} 安全对照: free 位于错误分支, 正常路径使用, 路径互斥. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {{
    char *p = (char *)malloc(64);
    if (!p) return 1;
    if (argc < 2) {{
        free(p);
        return 1;
    }}
    printf("%s\\n", p);
    free(p);
    return 0;
}}
""",
    "cleanup": """/* {cve} 安全对照: 释放结构体后读取字段指针用于二次 free, cleanup 语义. */
#include <stdlib.h>

struct S {{
    char *data;
}};

int main(int argc, char **argv) {{
    struct S *s = (struct S *)malloc(sizeof(struct S));
    if (!s) return 1;
    s->data = (char *)malloc(16);
    free(s);
    free(s->data);
    return 0;
}}
""",
}

MAKEFILE = """# {sample} 编译入口.
# Windows (mingw) 产出 vuln.exe (PE), Linux 产出 vuln (ELF).
CC ?= gcc
CFLAGS ?= -O0 -Wall -Wno-stringop-overflow

EXE = vuln$(if $(filter Windows_NT,$(OS)),.exe,)

all: $(EXE)

$(EXE): vuln.c
	$(CC) $(CFLAGS) vuln.c -o $@

O2: vuln.c
	$(CC) -O2 -Wall -Wno-stringop-overflow vuln.c -o vuln_O2$(if $(filter Windows_NT,$(OS)),.exe,)

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

{vuln} 代码在 {trigger} 后使用已释放指针, 构成 use-after-free
(CWE-416).

## 为何该样本可验证检测器有效性

- free->use 的指针流可从反汇编恢复 (寄存器/栈槽对象映射).
- 期望 {expected} 判定: 检测器应在不丢失召回的前提下
  区分真实 UAF 与指针复活/置空/路径互斥/cleanup 安全模式.
"""

TRIGGERS = {
    "printf_use": "free(p)",
    "strlen_use": "free(p)",
    "memcpy_use": "free(p)",
    "memset_use": "free(p)",
    "write_deref": "free(p)",
    "reborn_call": "free(p) 之后 p = get_ptr() 复活",
    "reborn_malloc": "free(p) 之后 p = malloc(64) 复活",
    "nulled_guard": "free(p) 之后 p = NULL 置空",
    "error_path": "free(p) 位于错误分支",
    "cleanup": "free(s) 之后读取 s->data 用于二次 free",
}


def select_template(pattern: str, is_vuln: bool):
    if not is_vuln:
        return _SAFE_TEMPLATES[pattern]
    return _VULN_TEMPLATES[pattern]
