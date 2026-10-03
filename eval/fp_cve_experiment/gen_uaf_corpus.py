"""UAF 语料库生成器 — 从 uaf_corpus_specs 生成样本目录并编译.

用法: python eval/fp_cve_experiment/gen_uaf_corpus.py [--skip-compile]
输出: corpus_uaf/<id>/{vuln.c, Makefile, README.md, truth.json, vuln.exe}
"""
import argparse
import json
import os
import subprocess
import sys

from _common import HERE as _HERE
from uaf_corpus_specs import UAF_TP_SAMPLES, UAF_FP_SAMPLES

CORPUS = os.path.join(_HERE, 'corpus_uaf')
CC = os.environ.get('CC', 'gcc')


def write_sample(sample: dict, vuln: bool) -> str:
    sid = sample['id']
    d = os.path.join(CORPUS, sid)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'vuln.c'), 'w', encoding='utf-8') as f:
        f.write(sample['src'].lstrip('\n'))
    with open(os.path.join(d, 'Makefile'), 'w', encoding='utf-8') as f:
        f.write('CC ?= gcc\n'
                'CFLAGS ?= -O0 -g -fno-stack-protector\n\n'
                'all: vuln.exe\n\n'
                'vuln.exe: vuln.c\n'
                '\t$(CC) $(CFLAGS) -o $@ vuln.c\n\n'
                'clean:\n'
                '\trm -f vuln.exe\n')
    truth = {
        'id': sid, 'expected_vuln': vuln,
        'vuln_type': 'use_after_free' if vuln else 'safe',
        'mode': sample.get('mode', ''),
    }
    with open(os.path.join(d, 'truth.json'), 'w', encoding='utf-8') as f:
        json.dump(truth, f, indent=2, ensure_ascii=False)
    readme = ('# %s\n\n'
              '| 字段 | 值 |\n'
              '|---|---|\n'
              '| 预期 | %s |\n'
              '| 模式 | %s |\n\n'
              '## 说明\n\n%s\n' % (
                  sid, '漏洞(UAF)' if vuln else '安全',
                  sample.get('mode', ''), sample.get('mode', '')))
    with open(os.path.join(d, 'README.md'), 'w', encoding='utf-8') as f:
        f.write(readme)
    return d


def compile_sample(d: str) -> bool:
    for flag, extra, exe in (('-O0', [], 'vuln.exe'),
                             ('-O2', ['-fno-dce'], 'vuln_O2.exe')):
        out = os.path.join(d, exe)
        if os.path.exists(out):
            continue
        proc = subprocess.run(
            [CC, flag] + extra + ['-g', '-fno-stack-protector',
             os.path.join(d, 'vuln.c'), '-o', out],
            capture_output=True, text=True)
        if proc.returncode != 0:
            print('  COMPILE FAIL', d, proc.stderr[:160])
            return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--skip-compile', action='store_true')
    args = ap.parse_args()
    n = 0
    for s in UAF_TP_SAMPLES:
        d = write_sample(s, vuln=True)
        if not args.skip_compile and compile_sample(d):
            n += 1
        print('TP :', s['id'])
    for s in UAF_FP_SAMPLES:
        d = write_sample(s, vuln=False)
        if not args.skip_compile and compile_sample(d):
            n += 1
        print('FP :', s['id'])
    with open(os.path.join(CORPUS, 'manifest.json'), 'w',
              encoding='utf-8') as f:
        json.dump({'tp': len(UAF_TP_SAMPLES),
                   'fp': len(UAF_FP_SAMPLES), 'compiled': n}, f, indent=2)
    print('uaf corpus ready:', os.path.join(CORPUS, 'manifest.json'))


if __name__ == '__main__':
    main()
