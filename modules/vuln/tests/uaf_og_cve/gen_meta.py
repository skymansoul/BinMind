"""UAF-OG 样本元数据生成器 — Makefile / truth.json / README.

  - 与 heap_fp_cve 的 gen_meta/gen_readmes 同构, 独立目录独立脚本.
  - truth.json 类别按目录名前缀: uaf-og- → TP, tn-og- → TN.
  - vuln.c 首块注释提取 CVE 与模式描述.
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
	$ $(CFLAGS) -o $@ vuln.c

vuln.exe: vuln.c
	$ $(CFLAGS) -o $@ vuln.c

clean:
	rm -f vuln vuln.exe
"""

README_TPL = """# {name}

- CVE: {cve}
- 模式: {desc}
- 触发条件: {trigger}
- 类别: {cls} ({kind})
- 为何有效: 独立目录, vuln.c + Makefile, 可编译为 PE/ELF 后由
  UAF-OG 代际分析管线 (反汇编→代际转移→判决压缩) 一键分析.
- 期望: {expect}
"""

KIND = {'TP': '漏洞样本 (真阳性)', 'TN': '安全对照 (真阴性)'}
EXPECT = {'TP': '检出 (kept > 0)', 'TN': '压制至无检出 (kept == 0)'}


def parse_header(src: Path) -> dict:
    text = src.read_text(encoding='utf-8', errors='replace')
    m = re.search(r'/\*(.*?)\*/', text, re.S)
    head = m.group(1) if m else ''
    first = head.splitlines()[0].strip() if head else ''
    cve = ''
    m2 = re.search(r'CVE-\d{4}-\d+', first)
    if m2:
        cve = m2.group(0)
    desc = ' '.join(first.split())[:160]
    trigger = ' '.join(head.splitlines()[1:2])[:200] if head else ''
    return {'cve': cve, 'desc': desc, 'trigger': trigger}


def main() -> int:
    n = 0
    for d in sorted(SAMPLES_DIR.iterdir()):
        if not d.is_dir():
            continue
        src = d / 'vuln.c'
        if not src.exists():
            continue
        info = parse_header(src)
        cls = 'TN' if d.name.startswith('tn-') else 'TP'
        mf = d / 'Makefile'
        if not mf.exists():
            mf.write_text(MAKEFILE, encoding='utf-8')
            n += 1
        tj = d / 'truth.json'
        if not tj.exists():
            tj.write_text(json.dumps(
                {'class': cls, 'cve': info['cve'], 'desc': info['desc'],
                 'trigger': info['trigger']},
                ensure_ascii=False, indent=2), encoding='utf-8')
            n += 1
        rd = d / 'README.md'
        if not rd.exists():
            rd.write_text(README_TPL.format(
                name=d.name, cve=info['cve'] or '(复现片段)',
                desc=info['desc'], trigger=info['trigger'] or '(见源码注释)',
                cls=cls, kind=KIND[cls], expect=EXPECT[cls]),
                encoding='utf-8')
            n += 1
    print(f'generated {n} files')
    return 0


if __name__ == '__main__':
    sys.exit(main())
