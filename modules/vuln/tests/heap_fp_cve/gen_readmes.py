"""README 与 truth.json 生成器 — 从 vuln.c 头注释提取元信息.

  - vuln.c 首块注释约定: 首行含 CVE 与模式, 后续行含触发条件.
  - README 结构固定: 样本ID/CVE/触发条件/为何有效/期望类别.
  - truth.json 类别由目录名前缀推导, CVE 从注释提取, 手工文件优先.
"""

import json
import re
import sys
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent / 'samples'


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


TEMPLATE = """# {name}

- CVE: {cve}
- 模式: {desc}
- 触发条件: {trigger}
- 类别: {cls} ({kind})
- 为何有效: 独立目录, vuln.c + Makefile, 可编译为 PE/ELF 后由
  ACFPC 管线 (反汇编→检测→误报压缩) 一键分析.
- 期望: {expect}
"""

KIND = {'TP': '漏洞样本 (真阳性)', 'TN': '安全对照 (真阴性)'}
EXPECT = {
    'TP': '检出 (kept > 0), 供召回率验证',
    'TN': '压制至无检出 (kept == 0), 供误报率验证',
}


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
        readme = d / 'README.md'
        if not readme.exists():
            readme.write_text(TEMPLATE.format(
                name=d.name, cve=info['cve'] or '(复现片段)',
                desc=info['desc'], trigger=info['trigger'] or '(见源码注释)',
                cls=cls, kind=KIND[cls], expect=EXPECT[cls]),
                encoding='utf-8')
            n += 1
        tj = d / 'truth.json'
        if not tj.exists():
            tj.write_text(json.dumps(
                {'class': cls, 'cve': info['cve'], 'desc': info['desc'],
                 'trigger': info['trigger']},
                ensure_ascii=False, indent=2), encoding='utf-8')
            n += 1
    print(f'generated {n} files')
    return 0


if __name__ == '__main__':
    sys.exit(main())
