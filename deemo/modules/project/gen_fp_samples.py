# FP-Reduction 基准样本生成器: 15 个堆溢出 + 10 个安全(误报陷阱)样本
# 设计目标:
#   fp_heapXX — 复刻真实 CVE 的堆溢出触发模式, 默认参数即触发运行时溢出
#     (QEMU 动态追踪作为 ground truth 的前提)
#   fp_safeXX — 真实代码中常见且安全、但通用静态工具必报的 idiom:
#     同源大小耦合 (malloc(n); memcpy(p,s,n)), 受钳位/守卫保护的写入,
#     结构体柔性数组, calloc 元素倍率, 分配器对齐余量等
# 样本结构: 每样本独立目录 {main.c, Makefile, README.md}
# 生成后不可手工修改, 修改须改本生成器后重新生成
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
OUT = ROOT / "fp_samples"

HEAP_COMMON = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
"""

SAFE_COMMON = """#include <stdio.h>
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


def readme(name, cve, vuln_type, severity, desc, pattern, trigger, fp_note,
           expected):
    return f"""# {name}

## CVE信息
- **CVE编号**: {cve}
- **漏洞类型**: {vuln_type}
- **严重级别**: {severity}

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
- 若为 `heap_overflow`: 检测器应报告DEFINITE_OVERFLOW或POSSIBLE_OVERFLOW
- 若为 `safe`: 检测器应报告0个发现
{expected}
"""


from .gen_fp_samples_data import SAMPLES

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    n = 0
    for name, spec in SAMPLES.items():
        d = OUT / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "main.c").write_text(spec["src"], encoding="utf-8")
        (d / "Makefile").write_text(makefile(name), encoding="utf-8")
        (d / "README.md").write_text(readme(
            name, spec["cve"], spec["vtype"], spec["sev"],
            spec["desc"], spec["pattern"], spec["trigger"],
            spec["fp_note"], spec["expected"]), encoding="utf-8")
        n += 1
        print(f"  [OK] {name}")
    print(f"生成 {n} 个样本于 {OUT}")


if __name__ == "__main__":
    sys.exit(main())
