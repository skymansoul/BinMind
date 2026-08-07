# UAF FP-Reduction 样本生成器: 2 漏洞 + 3 安全(误报陷阱)样本
# 设计目标:
#   uaf11/12 — 真实 UAF 触发模式 (双重释放别名 / 已知 sink 解引用)
#   uaf13-15 — 通用 UAF 检测器必报、实际安全的模式:
#     uaf13: 值传递 (printf("%p", freed)) — 未知函数传参误报类
#     uaf14: 非堆释放 (栈/全局缓冲) 后使用
#     uaf15: free 后重新分配/置 NULL 的再使用
# 样本结构: 每样本独立目录 {main.c, Makefile, README.md}
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
OUT = ROOT / "uaf_samples"

COMMON = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

run: $(TARGET)
\t./$(TARGET)
"""


def readme(name, cve, vtype, sev, desc, pattern, trigger, fp_note,
           expected):
    return f"""# {name}

## CVE信息
- **CVE编号**: {cve}
- **漏洞类型**: {vtype}
- **严重级别**: {sev}

## 漏洞描述
{desc}

## 溢出模式
`{pattern}`

## 编译
```bash
make
```

## 触发条件
{trigger}

## 为何对FP Reduction有效
{fp_note}

## 检测器预期行为
- 若为 `uaf`: 检测器应报告 UAF finding
- 若为 `safe`: 检测器应报告 0 个有效 finding
{expected}
"""


SAMPLES = {
    "uaf11_double_free_alias": dict(
        cve="CVE-2021-3156 模式", vtype="uaf", sev="MEDIUM",
        desc="双重释放: 别名指针 q 与 p 指向同一分配, 分别 free",
        pattern="double_free_alias",
        trigger="free(p) 后 free(q), 第二次释放即双重释放",
        fp_note="别名悬挂传播 + 释放时悬挂检测 → 双重释放检出",
        expected="预期检出: DOUBLE_FREE",
        src=COMMON + """int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    char *q = p;
    free(p);
    free(q);
    return 0;
}
"""),
    "uaf12_strlen_after_free": dict(
        cve="CVE-2017-1000251 模式", vtype="uaf", sev="HIGH",
        desc="释放后经已知读取 sink (strlen) 解引用",
        pattern="deref_known_sink",
        trigger="free(p) 后 strlen(p)",
        fp_note="已知 DEREF sink 传参 → 不受值传递抑制影响, 必须检出",
        expected="预期检出: CALL_ARG_PTR (HIGH)",
        src=COMMON + """int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "hello");
    free(p);
    size_t n = strlen(p);
    printf("%zu\\n", n);
    return 0;
}
"""),
    "uaf13_printf_valpass": dict(
        cve="无 (值传递 idiom)", vtype="safe", sev="NONE",
        desc="printf(\"%p\", freed_ptr): 悬挂指针仅作值传递, 不解引用",
        pattern="value_pass",
        trigger="任意: free 后打印指针值, 运行时无 UAF",
        fp_note="未知函数传参无法证实解引用 → 值传递抑制 (INFO+FP标记); "
                "通用检测器必报 MEDIUM 误报",
        expected="预期: 0 有效 finding (值传递抑制)",
        src=COMMON + """int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    printf("addr=%p\\n", (void *)p);
    return 0;
}
"""),
    "uaf14_free_nonheap": dict(
        cve="无 (非堆释放)", vtype="safe", sev="NONE",
        desc="栈/全局缓冲被 free 后继续使用; free 非堆对象是错误, "
             "但后续使用不构成堆 UAF",
        pattern="nonheap_free",
        trigger="任意: 栈缓冲 free 后写, 运行时无堆 UAF",
        fp_note="释放参数无堆溯源 → 堆溯源门控不标记悬挂",
        expected="预期: 0 finding (堆溯源门控)",
        src=COMMON + """static char g_buf[64];

int main(int argc, char **argv) {
    char stack_buf[64];
    char *q = stack_buf;
    free(q);
    q[0] = 'X';
    char *gp = g_buf;
    free(gp);
    gp[0] = 'Y';
    printf("%c%c\\n", q[0], gp[0]);
    return 0;
}
"""),
    "uaf15_rebind_after_free": dict(
        cve="无 (重绑定)", vtype="safe", sev="NONE",
        desc="free 后重新分配或置 NULL, 再使用指向新对象",
        pattern="rebind_after_free",
        trigger="任意: free(p); p=malloc(n) 后使用 p 指向新对象",
        fp_note="寄存器覆写/栈槽清除/NULL 守卫均被追踪 → 无悬挂残留",
        expected="预期: 0 finding",
        src=COMMON + """int main(int argc, char **argv) {
    char *p = (char *)malloc(32);
    if (!p) return 1;
    free(p);
    p = (char *)malloc(64);
    if (!p) return 1;
    p[0] = 'Z';
    free(p);
    p = NULL;
    if (p) *p = 1;
    printf("%c\\n", 'Z');
    return 0;
}
"""),
}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, spec in SAMPLES.items():
        d = OUT / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "main.c").write_text(spec["src"], encoding="utf-8")
        (d / "Makefile").write_text(makefile(name), encoding="utf-8")
        (d / "README.md").write_text(readme(
            name, spec["cve"], spec["vtype"], spec["sev"], spec["desc"],
            spec["pattern"], spec["trigger"], spec["fp_note"],
            spec["expected"]), encoding="utf-8")
        print(f"  [OK] {name}")
    print(f"生成 {len(SAMPLES)} 个样本于 {OUT}")


if __name__ == "__main__":
    sys.exit(main())
