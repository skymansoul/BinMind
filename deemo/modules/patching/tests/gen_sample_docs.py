# 样本文档补齐 — 为堆溢出样本生成缺失的Makefile与README
"""为缺Makefile/README的堆溢出样本补齐两类文件。
Makefile: 支持 debug/release 两种构建, 与compile_samples.py一致。
README:   提取vuln.c头注释作为CVE描述, 补充触发条件与检测要点。

决策逻辑:
  - 已存在的Makefile/README绝不覆盖(功能只增不减)
  - 缺失时基于vuln.c注释生成, 保证每个样本目录自洽
"""

import os
import re

SAMPLE_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'cve_samples')

MAKEFILE_TMPL = """# 构建目标: %(name)s
# 用法: make            → 生成 vuln_debug
#       make release    → 生成 vuln_release
CC ?= gcc
CFLAGS_DEBUG   := -g -O0
CFLAGS_RELEASE := -O2

all: vuln_debug

vuln_debug: vuln.c
\t$ $(CFLAGS_DEBUG) -o $@ vuln.c

vuln_release: vuln.c
\t$ $(CFLAGS_RELEASE) -o $@ vuln.c

clean:
\trm -f vuln_debug vuln_release

.PHONY: all clean
"""

README_TMPL = """# %(name)s

# CVE / 漏洞描述

%(desc)s

# 触发条件

%(trigger)s

# 为何有效

%(why)s

# 构建

```sh
make          # vuln_debug (gcc -g -O0)
make release  # vuln_release (gcc -O2)
```

# 检测要点

- 分配侧: %(alloc)s
- 写入侧: %(write)s
- 期望结果: %(expect)s
"""


def read_c_header(src_path: str) -> str:
    """提取vuln.c开头的块注释作为描述。"""
    try:
        with open(src_path, encoding='utf-8', errors='replace') as f:
            head = f.read(4000)
    except OSError:
        return ""
    # 匹配 /** ... */ 或 /* ... */
    m = re.search(r'/\*.*?\*/', head, re.S)
    return m.group(0) if m else ""


def sanitize(comment: str) -> str:
    """去掉注释标记与乱码, 保留可读描述。"""
    text = re.sub(r'/\*|\*/|^\s*\*', '', comment, flags=re.M)
    text = re.sub(r'[ \t]{2,}', ' ', text)
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return '\n'.join(lines[:12])


def describe_vuln_c(vuln_c_text: str) -> dict:
    """从vuln.c提取分配/写入/期望信息。"""
    info = {'desc': '', 'alloc': 'malloc/calloc/realloc', 'write': 'memcpy类',
            'expect': 'TP(检出为漏洞)'}
    low = vuln_c_text[:3000]
    for pat in ('malloc', 'calloc', 'realloc'):
        if pat in low:
            info['alloc'] = pat
    for pat in ('memcpy', 'strcpy', 'memmove', 'strncpy'):
        if pat in low:
            info['write'] = pat
            break
    if re.search(r'FP|safe|guarded|安全', low):
        info['expect'] = 'FP(应被过滤, 不报漏洞)'
    if re.search(r'loop|循环', low):
        info['write'] = '循环内逐字节写(loop_write)'
    return info


def main():
    made = []
    skipped = []
    heap_cves = {
        'CVE-2015-0235', 'CVE-2016-10191', 'CVE-2018-1000001',
        'CVE-2021-3156', 'CVE-2023-27997', 'CVE-2024-21626',
    }
    for d in sorted(os.listdir(SAMPLE_ROOT)):
        # 覆盖全部CVE-2025样本 + 含malloc的真实CVE样本
        src = os.path.join(SAMPLE_ROOT, d, 'vuln.c')
        if not os.path.isfile(src):
            continue
        has_malloc = False
        try:
            with open(src, encoding='utf-8', errors='replace') as f:
                has_malloc = 'malloc' in f.read(4000)
        except OSError:
            pass
        is_heap = (d.startswith('CVE-2025') or has_malloc)
        if not is_heap:
            continue
        sdir = os.path.join(SAMPLE_ROOT, d)
        if not os.path.isdir(sdir):
            continue
        src = os.path.join(sdir, 'vuln.c')
        if not os.path.isfile(src):
            continue
        vuln_text = open(src, encoding='utf-8', errors='replace').read()
        info = describe_vuln_c(vuln_text)
        comment = read_c_header(src)

        mk = os.path.join(sdir, 'Makefile')
        if not os.path.isfile(mk):
            with open(mk, 'w', encoding='utf-8', newline='\n') as f:
                f.write(MAKEFILE_TMPL % {'name': d})
            made.append(('Makefile', d))

        rd = os.path.join(sdir, 'README.md')
        if not os.path.isfile(rd):
            desc = sanitize(comment) or info['desc'] or d
            with open(rd, 'w', encoding='utf-8', newline='\n') as f:
                f.write(README_TMPL % {
                    'name': d, 'desc': desc,
                    'trigger': '构造可控输入触发分配大小与写入大小的不匹配',
                    'why': '分配大小与写入大小缺乏同步校验, 越界写入相邻堆块',
                    'alloc': info['alloc'], 'write': info['write'],
                    'expect': info['expect'],
                })
            made.append(('README', d))
        else:
            skipped.append(('README', d))

    print(f"补齐 {len(made)} 个文件:")
    for kind, name in made:
        print(f"  [{kind}] {name}")
    print(f"已存在跳过: {len(skipped)}")


if __name__ == '__main__':
    main()
