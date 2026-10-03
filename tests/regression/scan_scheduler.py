# 扫描调度模块 — 对编译后的样本调用BinMind扫描器
import os, subprocess, json, time, sys

def scan_binary(binary_path, output_dir):
    start = time.time()
    result = {'binary': binary_path, 'success': False, 'time_s': 0, 'findings': []}
    try:
        r = subprocess.run(
            [sys.executable, '-m', 'deemo', '--binary', binary_path,
             '--output-dir', output_dir, '--format', 'json', '--no-exec'],
            capture_output=True, timeout=120,
        )
        result['time_s'] = time.time() - start
        result['success'] = r.returncode == 0
        if r.stdout:
            try: result['findings'] = json.loads(r.stdout)
            except: result['raw'] = r.stdout[:500]
    except subprocess.TimeoutExpired:
        result['time_s'] = 120; result['error'] = 'timeout'
    except Exception as e:
        result['error'] = str(e)
    return result

def scan_all(samples_dir, output_base):
    results = {}
    for d in sorted(os.listdir(samples_dir)):
        dp = os.path.join(samples_dir, d)
        if not os.path.isdir(dp): continue
        for fname in os.listdir(dp):
            if fname.startswith('vuln') and '.' not in fname[4:]:
                bin_path = os.path.join(dp, fname)
                out_dir = os.path.join(output_base, d)
                os.makedirs(out_dir, exist_ok=True)
                results[d] = scan_binary(bin_path, out_dir)
                break
    return results

if __name__ == '__main__':
    import sys
    sd = sys.argv[1] if len(sys.argv) > 1 else '../cve_samples'
    od = sys.argv[2] if len(sys.argv) > 2 else '/tmp/deemo_results'
    r = scan_all(sd, od)
    print(json.dumps(r, indent=2, default=str))
