# 格式化字符串/整数溢出 FP-Reduction 样本生成器
# 目标: 验证两类检测器的 FP 抑制改进 (调用点上下文验证 / 回绕净化检测)
#   fmt_safe_* — 安全陷阱 (wrapper 实参常量 / 净化后回绕)
#   fmt_vuln_* / int_vuln_* — 漏洞对照 (保持检出)
# 样本语义: 独立目录 {main.c, Makefile, README.md}, 编译至 cve_samples/build/
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

## 为何对FP Reduction有效
{why}

## 检测器预期行为
- 若为 `vulnerable`: 检测器应报告有效 finding
- 若为 `safe`: 检测器应报告 0 个有效 finding (抑制标记不计)
"""


SAMPLES = {
    "fmt_safe_const_wrapper": dict(
        cve="无 (安全 wrapper)", vtype="safe", sev="NONE",
        desc="wrapper 内 printf(fmt), 所有调用点实参为常量字符串",
        pattern="const_call_sites",
        trigger="log_it(\"%s\", x) — 格式串固定",
        why="参数槽格式串 + 调用点实参全常量 → 调用点上下文验证抑制",
        src=COMMON + """static void log_it(char *fmt, char *data) {
    printf(fmt, data);
}

int main(int argc, char **argv) {
    char buf[32];
    strcpy(buf, "hello");
    log_it("%s", buf);
    log_it("%s", "world");
    return 0;
}
"""),
    "fmt_safe_param_multi": dict(
        cve="无 (多调用点常量)", vtype="safe", sev="NONE",
        desc="wrapper 的两个调用点均传常量格式串",
        pattern="multi_const_call_sites",
        trigger="show(\"%d\", a); show(\"%x\", b)",
        why="两处调用实参均为常量 → 抑制",
        src=COMMON + """static void show(char *fmt, int v) {
    printf(fmt, v);
}

int main(int argc, char **argv) {
    int a = 1, b = 2;
    show("%d", a);
    show("%x", b);
    return 0;
}
"""),
    "fmt_vuln_param_wrapper": dict(
        cve="CVE-2000-0573 模式", vtype="vulnerable", sev="HIGH",
        desc="wrapper 内 printf(fmt), 调用点实参来自 argv",
        pattern="user_call_site",
        trigger="log_it(argv[1]) — 格式串受攻击者控制",
        why="调用点实参为输入 → 验证不抑制, 保持检出",
        src=COMMON + """static void log_it(char *fmt) {
    printf(fmt);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    log_it(argv[1]);
    return 0;
}
"""),
    "int_safe_mask_after_add": dict(
        cve="无 (净化回绕)", vtype="safe", sev="NONE",
        desc="加法回绕结果被 AND 掩码限制到合法域",
        pattern="sanitized_wrap_and",
        trigger="x = 0xFFFF00; x += 0x200; x &= 0xFF",
        why="回绕后立即掩码 → 净化检测抑制",
        src=COMMON + """int main(int argc, char **argv) {
    unsigned int x = 0xFFFF00;
    x += 0x200;
    x &= 0xFF;
    printf("%u\\n", x);
    return 0;
}
"""),
    "int_safe_trunc_after_mul": dict(
        cve="无 (截断回绕)", vtype="safe", sev="NONE",
        desc="乘法回绕结果被零扩展截断到 8 位",
        pattern="sanitized_wrap_movzx",
        trigger="b = a * 0x100; c = (unsigned char)b",
        why="回绕后 movzx 截断 → 净化检测抑制",
        src=COMMON + """int main(int argc, char **argv) {
    unsigned int a = 0x10000;
    unsigned int b = a * 0x100;
    unsigned char c = (unsigned char)b;
    printf("%u\\n", c);
    return 0;
}
"""),
    "int_safe_shr_after_add": dict(
        cve="无 (右移回绕)", vtype="safe", sev="NONE",
        desc="加法回绕结果被右移缩小到合法域",
        pattern="sanitized_wrap_shr",
        trigger="x = 0xFFFFFFF0; x += 0x20; x >>= 4",
        why="回绕后右移 → 净化检测抑制",
        src=COMMON + """int main(int argc, char **argv) {
    unsigned int x = 0xFFFFFFF0;
    x += 0x20;
    x >>= 4;
    printf("%u\\n", x);
    return 0;
}
"""),
    "int_vuln_mask_missing": dict(
        cve="CVE-2018-14618 模式", vtype="vulnerable", sev="HIGH",
        desc="加法回绕后无净化, 直接用于分配",
        pattern="unsanitized_wrap",
        trigger="sz = 0xFFFFF000; sz += 0x1000; malloc(sz)",
        why="回绕后无净化指令 → 不抑制, 保持检出",
        src=COMMON + """int main(int argc, char **argv) {
    unsigned int sz = 0xFFFFF000;
    sz += 0x1000;
    char *p = (char *)malloc(sz);
    if (!p) return 1;
    memset(p, 'Z', 0x20);
    printf("%c\\n", p[0]);
    free(p);
    return 0;
}
"""),
}


def main():
    for name, spec in SAMPLES.items():
        d = OUT / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "main.c").write_text(spec["src"], encoding="utf-8")
        (d / "Makefile").write_text(makefile(name), encoding="utf-8")
        (d / "README.md").write_text(readme(
            name, spec["cve"], spec["vtype"], spec["sev"],
            spec["desc"], spec["pattern"], spec["trigger"], spec["why"]),
            encoding="utf-8")
        exe = BUILD / f"{name}.exe"
        r = subprocess.run(
            ["gcc", "-Wall", "-O0", "-fno-stack-protector", "-g",
             "-o", str(exe), str(d / "main.c")],
            capture_output=True, text=True, timeout=30)
        status = "OK" if r.returncode == 0 else "FAIL"
        print(f"  [{status}] {name}")
    print(f"生成 {len(SAMPLES)} 个样本")


if __name__ == "__main__":
    sys.exit(main())
