"""扫描调度: 对编译产物依次调用 BinMind, 输出 scan_results.json。
"""

import os, sys, json, subprocess, time, argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'deemo'))

BUILD_JSON = os.path.join(os.path.dirname(__file__), 'build_results.json')
OUTPUT_JSON = os.path.join(os.path.dirname(__file__), 'scan_results.json')
SCANNER_SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'deemo', 'binmind.py')


def load_build_results() -> list[dict]:
    with open(BUILD_JSON) as f:
        return json.load(f)


def run_binmind(binary_path: str, timeout_sec: int = 120) -> dict:
    t0 = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, SCANNER_SCRIPT, binary_path,
             '--format', 'json', '--max-funcs', '10', '--verbose'],
            capture_output=True, text=True, timeout=timeout_sec,
        )
        elapsed = time.time() - t0
        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()
        try:
            parsed = json.loads(stdout) if stdout else {}
        except json.JSONDecodeError:
            parsed = {'raw_output': stdout[:500]}

        return {
            'binary': binary_path,
            'success': proc.returncode == 0,
            'elapsed_sec': round(elapsed, 1),
            'findings': parsed.get('total_vulns', len(parsed.get('decomp_analysis', []))),
            'details': parsed,
            'stderr': stderr[:300],
        }
    except subprocess.TimeoutExpired:
        return {'binary': binary_path, 'success': False,
                'elapsed_sec': timeout_sec, 'findings': 0, 'error': 'timeout'}
    except FileNotFoundError:
        return {'binary': binary_path, 'success': False,
                'elapsed_sec': 0, 'findings': 0, 'error': 'binmind.py not found'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()

    if not os.path.isfile(BUILD_JSON):
        print(f'Build results not found: {BUILD_JSON}')
        print('Run build_samples.py first.')
        return

    builds = load_build_results()
    succeeded = [b for b in builds if b['success']]
    if not succeeded:
        print('No successfully compiled binaries found.')
        return

    results = []
    for b in succeeded:
        binary = b['binary']
        if not binary or not os.path.isfile(binary):
            continue
        label = f'{b["name"]} [{b["compiler"]} {b["opt"]}]'
        print(f'Scanning: {label}')
        r = run_binmind(binary, timeout_sec=args.timeout)
        r['label'] = label
        r['sample_name'] = b['name']
        r['compiler'] = b['compiler']
        r['opt_level'] = b['opt']
        results.append(r)
        print(f'  -> {r["findings"]} findings in {r["elapsed_sec"]}s')

    with open(OUTPUT_JSON, 'w') as f:
        json.dump(results, f, indent=2)
    print(f'\nScan complete: {len(results)} binaries')


if __name__ == '__main__':
    main()
