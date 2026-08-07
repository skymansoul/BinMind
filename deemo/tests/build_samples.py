# 创建: 2026-06-15
"""批量编译测试样本 — 遍历 cve_samples 目录, 调用 gcc/clang 生成 ELF。

输出: build_results.json — 每个样本的编译状态和路径。
"""

import os, sys, json, subprocess, glob

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), 'cve_samples')
OUTPUT_JSON = os.path.join(os.path.dirname(__file__), 'build_results.json')
COMPILERS = ['gcc', 'clang']
OPT_LEVELS = ['O0', 'O2']


def find_samples(base_dir: str) -> list[dict]:
    samples = []
    for entry in sorted(os.listdir(base_dir)):
        sample_dir = os.path.join(base_dir, entry)
        if not os.path.isdir(sample_dir):
            continue
        vuln_c = os.path.join(sample_dir, 'vuln.c')
        if not os.path.isfile(vuln_c):
            continue
        samples.append({'name': entry, 'dir': sample_dir, 'source': vuln_c})
    return samples


def compile_sample(sample: dict, compiler: str, opt: str) -> dict:
    name = sample['name']
    out_name = f'{name}_{compiler}_{opt}'
    out_path = os.path.join(sample['dir'], out_name)
    cmd = [compiler, f'-{opt}', '-o', out_path, sample['source']]
    # 栈溢出样本需关闭 canary
    if 'stack_overflow' in name or 'format_string' in name:
        cmd.insert(1, '-fno-stack-protector')
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        success = result.returncode == 0
        return {
            'name': name, 'compiler': compiler, 'opt': opt,
            'binary': out_path if success else None,
            'success': success,
            'stderr': result.stderr[:200] if not success else '',
        }
    except subprocess.TimeoutExpired:
        return {'name': name, 'compiler': compiler, 'opt': opt,
                'binary': None, 'success': False, 'stderr': 'timeout'}
    except FileNotFoundError:
        return {'name': name, 'compiler': compiler, 'opt': opt,
                'binary': None, 'success': False, 'stderr': f'{compiler} not found'}


def main():
    samples = find_samples(SAMPLES_DIR)
    if not samples:
        print(f'No samples found under {SAMPLES_DIR}')
        return

    results = []
    for sample in samples:
        for compiler in COMPILERS:
            for opt in OPT_LEVELS:
                r = compile_sample(sample, compiler, opt)
                status = 'OK' if r['success'] else 'FAIL'
                print(f'  {r["name"]} [{compiler} {opt}]: {status}')
                results.append(r)

    with open(OUTPUT_JSON, 'w') as f:
        json.dump(results, f, indent=2)

    ok = sum(1 for r in results if r['success'])
    print(f'\nCompiled: {ok}/{len(results)}')


if __name__ == '__main__':
    main()
