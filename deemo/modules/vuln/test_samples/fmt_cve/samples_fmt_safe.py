# coding: utf-8
# 创建: 2026-04-22  |  格式串语料数据 C——SAFE 样本
#
"""格式化字符串 SAFE 样本数据 (常量格式串, 误报削减目标)."""

SAMPLES_FMT_SAFE = [
    {
        "id": "fmt_safe_literal",
        "cve": "None (synthetic)",
        "title": "Literal constant format string",
        "pattern": "printf(\"hello %d\", x)",
        "trigger": "无 — 编译期常量格式串",
        "why": "lea [rip+off] → CONST; 旧检测不误报, 验证不失真",
        "code": r'''/* fmt_safe_literal — 字面常量格式串 (SAFE)。
 * Expected: SAFE */
#include <stdio.h>

int main(int argc, char **argv) {
    printf("hello %d\n", argc);
    return 0;
}
''',
    },
    {
        "id": "fmt_safe_literal_var",
        "cve": "None (synthetic)",
        "title": "Constant format via variable pointer",
        "pattern": "char*fmt=\"fixed %s\"; printf(fmt, s)",
        "trigger": "无 — 变量持有的常量格式串",
        "why": "槽→rodata 溯源 → CONST; 旧检测器对变量形式误报 → FP 削减目标",
        "code": r'''/* fmt_safe_literal_var — 变量持有的常量格式串 (SAFE)。
 * Expected: SAFE */
#include <stdio.h>

int main(void) {
    char *fmt = "fixed %s";
    printf(fmt, "world");         /* fmt 指向常量 */
    return 0;
}
''',
    },
    {
        "id": "fmt_safe_rodata_table",
        "cve": "None (synthetic)",
        "title": "Constant format from rodata table",
        "pattern": "const char *tbl[] = {\"a\",\"b\"}; printf(tbl[0])",
        "trigger": "无 — rodata 表项作格式串",
        "why": "rip 相对加载 → CONST; 旧检测器误报 → FP 削减目标",
        "code": r'''/* fmt_safe_rodata_table — rodata 表项格式串 (SAFE)。
 * Expected: SAFE */
#include <stdio.h>

static const char *tbl[] = {"item=%d\n", "done\n"};

int main(int argc, char **argv) {
    printf(tbl[0], argc);         /* 常量表项 */
    return 0;
}
''',
    },
    {
        "id": "fmt_safe_snprintf_const",
        "cve": "None (synthetic)",
        "title": "snprintf with constant format",
        "pattern": "snprintf(dst, 64, \"x=%d\", v)",
        "trigger": "无 — fmt 参数 (arg2) 为常量",
        "why": "fmt arg2 溯源到 lea rip → CONST",
        "code": r'''/* fmt_safe_snprintf_const — snprintf 常量格式 (SAFE)。
 * Expected: SAFE */
#include <stdio.h>

int main(int argc, char **argv) {
    char dst[64];
    snprintf(dst, sizeof(dst), "x=%d", argc);
    puts(dst);
    return 0;
}
''',
    },
]
