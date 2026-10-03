"""样本元数据生成器 — 为 samples 下全部目录生成 Makefile 与 truth.json.

  - Makefile 内容统一: 默认 -O0 -fno-stack-protector -fno-builtin,
    兼容 MinGW 与 Linux gcc, 产出 vuln/vuln.exe 双目标.
  - truth.json 按目录名前缀推导类别: heap-acfpc- 前缀为 TP (漏洞),
    tn-acfpc- 前缀为 TN (安全对照). 手工创建的 truth.json 优先.
  - 本脚本可重复执行, 不覆盖已存在的手工 truth.json.
"""

import json
import sys
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent / 'samples'

MAKEFILE = """CC ?= gcc
CFLAGS ?= -O0 -fno-stack-protector -fno-builtin

all: vuln vuln.exe

vuln: vuln.c
	$ $(CFLAGS) -o $@ vuln.c

vuln.exe: vuln.c
	$ $(CFLAGS) -o $@ vuln.c

clean:
	rm -f vuln vuln.exe
"""


def main() -> int:
    generated = 0
    for d in sorted(SAMPLES_DIR.iterdir()):
        if not d.is_dir():
            continue
        if not (d / 'vuln.c').exists():
            continue
        mf = d / 'Makefile'
        if not mf.exists():
            mf.write_text(MAKEFILE, encoding='utf-8')
            generated += 1
        tj = d / 'truth.json'
        if not tj.exists():
            cls = 'TN' if d.name.startswith('tn-') else 'TP'
            tj.write_text(json.dumps(
                {'class': cls, 'cve': '', 'desc': '', 'trigger': ''},
                ensure_ascii=False, indent=2), encoding='utf-8')
            generated += 1
    print(f'generated meta for {generated} files')
    return 0


if __name__ == '__main__':
    sys.exit(main())
