"""统一对比实验调度 — 将样本喂给 BinMind/Angr/QEMU/Ghidra, 收集并汇总指标。

输出: benchmark_results.json — 每个工具对每个样本的检测结果。
"""

import os, sys, json, time, subprocess, argparse

ROOT = os.path.dirname(os.path.dirname(__file__))
TESTS_DIR = os.path.join(ROOT, 'tests')
EXPERIMENTS_DIR = os.path.dirname(__file__)
DEEMO_DIR = os.path.join(ROOT, 'deemo')

RUNNERS = {
    'BinMind': {
        'script': os.path.join(EXPERIMENTS_DIR, '..', 'deemo', 'binmind.py'),
        'args': ['{binary}', '--format', 'json', '--max-funcs', '5'],
        'timeout': 120,
    },
    'Angr': {
        'script': os.path.join(EXPERIMENTS_DIR, 'angr_runner.py'),
        'args': ['{binary}'],
        'timeout': 120,
    },
    'QEMU': {
        'script': os.path.join(EXPERIMENTS_DIR, 'qemu_runner.py'),
        'args': ['{binary}'],
        'timeout': 60,
    },
    'Ghidra': {
        'script': os.path.join(EXPERIMENTS_DIR, 'ghidra_runner.py'),
        'args': ['{binary}'],
        'timeout': 180,
    },
}


def collect_binaries() -> list[dict]:
    """从 build_results.json 收集所有已编译的二进制。"""
    build_json = os.path.join(TESTS_DIR, 'build_results.json')
    if not os.path.isfile(build_json):
        return _manual_collect()
    with open(build_json) as f:
        builds = json.load(f)
    return [b for b in builds if b.get('success') and b.get('binary')
            and os.path.isfile(b['binary'])]


def _manual_collect() -> list[dict]:
    """无编译结果时, 手动收集 cve_samples 下已有的二进制。"""
    samples_dir = os.path.join(TESTS_DIR, 'cve_samples')
    binaries = []
    for root, dirs, files in os.walk(samples_dir):
        for f in files:
            path = os.path.join(root, f)
            if os.access(path, os.X_OK) and '.' not in os.path.basename(f):
                binaries.append({'binary': path, 'name': os.path.basename(root), 'compiler': 'unknown', 'opt': 'unknown'})
    return binaries


def run_tool(tool_name: str, config: dict, binary_path: str) -> dict:
    args = [arg.replace('{binary}', binary_path) for arg in config['args']]
    cmd = [sys.executable, config['script']] + args
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=config['timeout'])
        elapsed = round(time.time() - t0, 1)
        return {'tool': tool_name, 'binary': binary_path,
                'elapsed_sec': elapsed,
                'returncode': proc.returncode,
                'output': proc.stdout[:500],
                'error': proc.stderr[:200] if proc.returncode != 0 else ''}
    except subprocess.TimeoutExpired:
        return {'tool': tool_name, 'binary': binary_path,
                'elapsed_sec': config['timeout'], 'error': 'timeout'}
    except FileNotFoundError:
        return {'tool': tool_name, 'binary': binary_path,
                'elapsed_sec': 0, 'error': 'script not found'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tools', nargs='+', default=list(RUNNERS.keys()))
    parser.add_argument('--max-samples', type=int, default=20)
    args = parser.parse_args()

    binaries = collect_binaries()[:args.max_samples]
    if not binaries:
        print('No binaries found. Run tests/build_samples.py first.')
        return

    all_results = []
    for tool_name in args.tools:
        config = RUNNERS.get(tool_name)
        if config is None:
            continue
        for b in binaries:
            label = f'{tool_name} <- {b.get("name","?")}'
            print(f'  {label}')
            r = run_tool(tool_name, config, b['binary'])
            r['sample_name'] = b.get('name', '')
            all_results.append(r)

    out_path = os.path.join(EXPERIMENTS_DIR, 'benchmark_results.json')
    with open(out_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f'\nResults saved: {out_path}')


if __name__ == '__main__':
    main()
