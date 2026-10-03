"""格式化字符串样本集生成器 — 16 漏洞 + 8 安全样本。

每个目录含: vuln.c(触发程序), Makefile, README.md, truth.json。
运行: python samples/fmt_generate_samples.py
"""

import json
from pathlib import Path

from fmt_sample_defs_a import SAMPLE_DEFS_A
from fmt_sample_defs_b import SAMPLE_DEFS_B
from fmt_sample_defs_safe import SAMPLE_DEFS_SAFE

BASE = Path(__file__).resolve().parent
VULN_DIR = BASE / 'fmt_cve'
SAFE_DIR = BASE / 'fmt_fp'

MAKEFILE = """\
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
TARGET = vuln.exe

all: $(TARGET)

$(TARGET): vuln.c
\t$(CC) $(CFLAGS) -o $(TARGET) vuln.c

clean:
\trm -f $(TARGET)
"""


def readme_text(spec: dict, vuln: bool) -> str:
    kind = '格式化字符串 (format string)' if vuln else '安全样本 (无漏洞)'
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
        '程序从命令行读取外部输入, 直接驱动格式串路径:',
        '',
        '```',
        'vuln.exe <输入>   # 漏洞样本(格式参数由攻击者控制)',
        'vuln.exe <输入>   # 安全样本(格式为字面量来源)',
        '```',
        '',
        '## 为何有效',
        '',
        '样本把攻击者可控字符串直接或间接传入 printf 族格式参数,',
        '是检验"格式参数来源"判定精度的最小可复现单元; 安全样本',
        '专用于测量误报率。',
        '',
    ]
    return '\n'.join(lines)


def _write_if_changed(path: Path, text: str) -> None:
    """内容一致则跳过写入, 保持文件系统状态不变。"""
    if path.exists() and path.read_text(encoding='utf-8') == text:
        return
    path.write_text(text, encoding='utf-8')


def write_sample(dir_path: Path, spec: dict, vuln: bool) -> None:
    dir_path.mkdir(parents=True, exist_ok=True)
    _write_if_changed(dir_path / 'vuln.c', spec['source'])
    _write_if_changed(dir_path / 'Makefile', MAKEFILE)
    _write_if_changed(dir_path / 'README.md', readme_text(spec, vuln))
    truth = dict(spec['truth'])
    truth['cve'] = spec.get('cve', '')
    truth['func'] = spec['func']
    truth['name'] = spec['name']
    _write_if_changed(dir_path / 'truth.json',
                      json.dumps(truth, ensure_ascii=False, indent=2))


def main() -> None:
    n = 0
    for spec in SAMPLE_DEFS_A + SAMPLE_DEFS_B:
        write_sample(VULN_DIR / spec['name'], spec, vuln=True)
        n += 1
    for spec in SAMPLE_DEFS_SAFE:
        write_sample(SAFE_DIR / spec['name'], spec, vuln=False)
        n += 1
    print(f'[fmt-samples] generated {n} sample directories '
          f'({len(SAMPLE_DEFS_A + SAMPLE_DEFS_B)} vuln + '
          f'{len(SAMPLE_DEFS_SAFE)} safe)')


if __name__ == '__main__':
    main()
