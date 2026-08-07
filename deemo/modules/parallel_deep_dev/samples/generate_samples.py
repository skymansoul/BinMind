"""样本集生成器 — 输出 16 CVE 漏洞样本 + 8 安全样本。

每个目录含: vuln.c(触发程序), Makefile, README.md, truth.json。
运行: python samples/generate_samples.py
"""

import json
import os
from pathlib import Path

from sample_defs import SAMPLE_DEFS_A, SAMPLE_DEFS_B, SAMPLE_DEFS_SAFE

BASE = Path(__file__).resolve().parent
VULN_DIR = BASE / 'heap_overflow_cve'
SAFE_DIR = BASE / 'heap_safe_fp'

MAKEFILE = """\
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
TARGET = vuln.exe

all: $(TARGET)

$(TARGET): vuln.c
\t$ $(CFLAGS) -o $(TARGET) vuln.c

clean:
\trm -f $(TARGET)
"""


def readme_text(spec: dict, vuln: bool) -> str:
    kind = '堆溢出 (heap overflow)' if vuln else '安全样本 (无漏洞)'
    cve = spec.get('cve') or '无'
    lines = [
        f'# {spec["name"]}',
        '',
        f'- **类型**: {kind}',
        f'- **CVE**: {cve}',
        f'- **触发函数**: {spec["func"]}',
        '',
        '## 漏洞说明',
        '',
        spec['readme'].replace('\\n', '\n'),
        '',
        '## 触发条件',
        '',
        '程序从命令行读取外部长度与数据, 直接驱动漏洞路径:',
        '',
        '```',
        f'vuln.exe <长度> <数据>   # 漏洞样本(长度由攻击者控制)',
        f'vuln.exe <参数>          # 安全样本(数据流满足容量约束)',
        '```',
        '',
        '## 为何有效',
        '',
        '样本的分配与写入集中在同一函数内, 写入字节范围可由静态',
        '分析精确提取, 是检验"写范围 vs 分配容量"判定精度的最小',
        '可复现单元; 安全样本专用于测量误报率。',
        '',
    ]
    return '\n'.join(lines)


def write_sample(dir_path: Path, spec: dict, vuln: bool) -> None:
    dir_path.mkdir(parents=True, exist_ok=True)
    (dir_path / 'vuln.c').write_text(spec['source'], encoding='utf-8')
    (dir_path / 'Makefile').write_text(MAKEFILE, encoding='utf-8')
    (dir_path / 'README.md').write_text(
        readme_text(spec, vuln), encoding='utf-8')
    truth = dict(spec['truth'])
    truth['cve'] = spec.get('cve', '')
    truth['func'] = spec['func']
    truth['name'] = spec['name']
    (dir_path / 'truth.json').write_text(
        json.dumps(truth, ensure_ascii=False, indent=2), encoding='utf-8')


def main() -> None:
    n = 0
    for spec in SAMPLE_DEFS_A + SAMPLE_DEFS_B:
        write_sample(VULN_DIR / spec['name'], spec, vuln=True)
        n += 1
    for spec in SAMPLE_DEFS_SAFE:
        write_sample(SAFE_DIR / spec['name'], spec, vuln=False)
        n += 1
    print(f'[samples] generated {n} sample directories '
          f'({len(SAMPLE_DEFS_A + SAMPLE_DEFS_B)} vuln + '
          f'{len(SAMPLE_DEFS_SAFE)} safe)')


if __name__ == '__main__':
    main()
