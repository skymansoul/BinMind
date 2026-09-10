"""堆溢出语料库生成器 — 从 corpus_specs 生成样本目录并编译.

用法: python eval/fp_cve_experiment/gen_corpus.py [--skip-compile]
输出: corpus/<id>/{vuln.c, Makefile, README.md, truth.json, vuln.exe}
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

from _common import HERE as _HERE
from corpus_specs import CVE_SAMPLES, SAFE_SAMPLES

CORPUS_DIR = os.path.join(_HERE, 'corpus')
CC = os.environ.get('CC', 'gcc')


def write_sample(sample: dict, vuln: bool) -> str:
    sid = sample['id']
    d = os.path.join(CORPUS_DIR, sid)
    os.makedirs(d, exist_ok=True)
    src = sample['src'].lstrip('\n')
    with open(os.path.join(d, 'vuln.c'), 'w', encoding='utf-8') as f:
        f.write(src)
    makefile = (
        'CC ?= gcc\n'
        'CFLAGS ?= -O0 -g -fno-stack-protector\n\n'
        'all: vuln.exe\n\n'
        'vuln.exe: vuln.c\n'
        '\t$(CC) $(CFLAGS) -o $@ vuln.c\n\n'
        'clean:\n'
        '\trm -f vuln.exe\n')
    with open(os.path.join(d, 'Makefile'), 'w', encoding='utf-8') as f:
        f.write(makefile)
    truth = {
        'id': sid,
        'expected_vuln': vuln,
        'vuln_type': sample.get('vuln_type',
                                'safe' if not vuln else 'heap_overflow'),
        'cve': sample.get('cve', ''),
        'component': sample.get('component', ''),
        'mode': sample.get('mode', ''),
    }
    with open(os.path.join(d, 'truth.json'), 'w', encoding='utf-8') as f:
        json.dump(truth, f, indent=2, ensure_ascii=False)
    if vuln:
        readme = (
            '# %s\n\n'
            '| 字段 | 值 |\n'
            '|---|---|\n'
            '| CVE | %s |\n'
            '| 组件 | %s |\n'
            '| 模式 | %s |\n'
            '| 类型 | %s |\n\n'
            '## 触发条件\n\n'
            '%s\n\n'
            '## 为何有效\n\n'
            '本样本将CVE的核心缺陷模式还原为自包含C程序: %s。\n'
            '编译选项 -O0/-O2 均可, 反汇编中 malloc 调用点、写入指令'
            '与真实CVE的汇编形态一致。\n' % (
                sid, sample.get('cve', ''), sample.get('component', ''),
                sample.get('mode', ''), sample.get('vuln_type', ''),
                sample.get('mode', ''), sample.get('mode', '')))
    else:
        readme = (
            '# %s\n\n'
            '| 字段 | 值 |\n'
            '|---|---|\n'
            '| 预期 | 安全(无堆溢出) |\n'
            '| 误报模式 | %s |\n\n'
            '## 说明\n\n'
            '%s\n' % (sid, sample.get('mode', ''), sample.get('mode', '')))
    with open(os.path.join(d, 'README.md'), 'w', encoding='utf-8') as f:
        f.write(readme)
    return d


def compile_sample(d: str) -> bool:
    for flag, extra in (('-O0', []), ('-O2', ['-fno-dce'])):
        exe = os.path.join(d, 'vuln.exe') if flag == '-O0' else \
            os.path.join(d, 'vuln_O2.exe')
        if os.path.exists(exe):
            continue
# fno-dce: 防止O2死存储消除移除未观测的堆写入, 保持漏洞语义
        proc = subprocess.run(
            [CC, flag] + extra + ['-g', '-fno-stack-protector',
             os.path.join(d, 'vuln.c'), '-o', exe],
            capture_output=True, text=True)
        if proc.returncode != 0:
            print('  COMPILE FAIL', d, proc.stderr[:200])
            return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--skip-compile', action='store_true')
    args = ap.parse_args()
    n = 0
    for sample in CVE_SAMPLES:
        d = write_sample(sample, vuln=True)
        if not args.skip_compile and compile_sample(d):
            n += 1
        print('CVE :', sample['id'])
    for sample in SAFE_SAMPLES:
        d = write_sample(sample, vuln=False)
        if not args.skip_compile and compile_sample(d):
            n += 1
        print('SAFE:', sample['id'])
    manifest = {
        'cve_count': len(CVE_SAMPLES),
        'safe_count': len(SAFE_SAMPLES),
        'compiled': n,
    }
    with open(os.path.join(CORPUS_DIR, 'manifest.json'), 'w',
              encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)
    print('corpus ready:', os.path.join(CORPUS_DIR, 'manifest.json'))


if __name__ == '__main__':
    main()
