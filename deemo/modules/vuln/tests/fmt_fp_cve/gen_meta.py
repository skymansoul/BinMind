"""Fmt-OG 样本元数据生成器 — Makefile / truth.json / README.

truth.json 类别按目录名前缀: fmt-tp- → TP, fmt-tn- → TN.
vuln.c 首块注释提取漏洞模式描述.
"""

import json
import re
import sys
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent / 'samples'

MAKEFILE = """CC ?= gcc
CFLAGS ?= -O0 -fno-stack-protector -fno-builtin

all: vuln vuln.exe

vuln: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

vuln.exe: vuln.c
	$(CC) $(CFLAGS) -o $@ vuln.c

clean:
	rm -f vuln vuln.exe
"""

README_TPL = """# {name}

- 模式: {desc}
- 类别: {cls} ({kind})
- 期望: {expect}
"""

KIND = {'TP': '漏洞样本 (真阳性)', 'TN': '安全对照 (真阴性)'}
EXPECT = {'TP': '检出 (kept > 0)', 'TN': '压制至无检出 (kept == 0)'}


def parse_header(src: Path) -> str:
    text = src.read_text(encoding='utf-8', errors='replace')
    m = re.search(r'/\*(.*?)\*/', text, re.S)
    head = m.group(1) if m else ''
    first = head.splitlines()[0].strip() if head else ''
    return ' '.join(first.split())[:160]


def main() -> int:
    n = 0
    for d in sorted(SAMPLES_DIR.iterdir()):
        if not d.is_dir():
            continue
        src = d / 'vuln.c'
        if not src.exists():
            continue
        desc = parse_header(src)
        cls = 'TN' if d.name.startswith('fmt-tn-') else 'TP'
        mf = d / 'Makefile'
        if not mf.exists():
            mf.write_text(MAKEFILE, encoding='utf-8')
            n += 1
        tj = d / 'truth.json'
        if not tj.exists():
            tj.write_text(json.dumps(
                {'class': cls, 'desc': desc},
                ensure_ascii=False, indent=2), encoding='utf-8')
            n += 1
        rd = d / 'README.md'
        if not rd.exists():
            rd.write_text(README_TPL.format(
                name=d.name, desc=desc, cls=cls, kind=KIND[cls],
                expect=EXPECT[cls]), encoding='utf-8')
            n += 1
    print(f'generated {n} files')
    return 0


if __name__ == '__main__':
    sys.exit(main())
