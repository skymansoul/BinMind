"""回归测试扫描调度 -- 自动编译样本+调用扫描器+收集结果。

架构: 编译模块(compile_samples) → 扫描调度(本模块) → 结果解析(result_parser)
模块间通过JSON文件传递数据, 无直接import依赖。
"""
import json, os, subprocess, sys, time, argparse

BINMIND_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), '..', 'cve_samples')
RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')

def find_binaries(samples_dir):
    binaries = []
    for root, dirs, files in os.walk(samples_dir):
        for f in files:
            path = os.path.join(root, f)
            if not f.endswith('.c') and not f.endswith('.md') and not f.endswith('.py'):
                if os.access(path, os.X_OK) or 'ELF' in _file_type(path):
                    binaries.append(path)
    for f in files:
        path = os.path.join(root, f)
        if '.' not in f and os.access(path, os.X_OK):
            if path not in binaries:
                binaries.append(path)
    return binaries

def _file_type(path):
    try:
        return subprocess.check_output(['file', path], text=True, timeout=5)
    except Exception:
        return ''

def run_scan(binary_path, scan_type='stack_overflow'):
    cmd = [sys.executable, '-m', 'binmind', 'scan', binary_path,
           '--type', scan_type, '--output', 'json']
    try:
        start = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=120, cwd=BINMIND_ROOT)
        elapsed = time.time() - start
        return {'ok': True, 'stdout': proc.stdout, 'stderr': proc.stderr,
                'elapsed': elapsed, 'returncode': proc.returncode}
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'timeout', 'elapsed': 120.0}
    except Exception as e:
        return {'ok': False, 'error': str(e), 'elapsed': 0}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--type', default='all', help='stack_overflow|format_string|heap|all')
    parser.add_argument('--output', default=None, help='Output JSON path')
    args = parser.parse_args()

    os.makedirs(RESULTS_DIR, exist_ok=True)
    binaries = find_binaries(SAMPLES_DIR)

    if not binaries:
        print("No binaries found. Run compile_samples.py first.")
        return 1

    scan_types = ['stack_overflow', 'format_string', 'heap'] if args.type == 'all' else [args.type]
    results = []

    for binary in binaries:
        sample_name = os.path.basename(os.path.dirname(binary))
        for stype in scan_types:
            r = run_scan(binary, stype)
            r['binary'] = binary
            r['sample'] = sample_name
            r['scan_type'] = stype
            results.append(r)
            status = 'OK' if r['ok'] else f'FAIL({r.get("error","")})'
            print(f'[{stype:15s}] {sample_name:30s} {status:20s} {r["elapsed"]:.1f}s')

    out_path = args.output or os.path.join(RESULTS_DIR, 'scan_results.json')
    with open(out_path, 'w') as f:
        json.dump({'timestamp': time.time(), 'results': results}, f, indent=2)
    print(f'\nResults saved to {out_path}')
    return 0

if __name__ == '__main__':
    sys.exit(main())
