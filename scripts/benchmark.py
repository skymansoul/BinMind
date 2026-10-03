#!/usr/bin/env python3
"""LLM 量化对比基准 — subprocess 方式调用 binmind.py analyze。

每组样本分别以 llm 关/开两种模式运行, 收集耗时与漏洞数,
结果追加到 logs/benchmark_results.csv。不直接导入 run_pipeline,
避免环境变量污染。
"""
import csv
import os
import re
import subprocess
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CSV_PATH = os.path.join(_ROOT, 'logs', 'benchmark_results.csv')


def run_benchmark(sample_list, llm_enabled=False):
    """对样本列表逐个运行 analyze, 返回 (sample, llm, 耗时, 漏洞数, 返回码) 行。"""
    env = os.environ.copy()
    if llm_enabled:
        if not (env.get('OPENAI_API_KEY') or env.get('ANTHROPIC_API_KEY')):
            print('[WARN] llm_enabled=True 但无 API key, 跳过该组', file=sys.stderr)
            return []
        env['ENABLE_LLM_TRIAGE'] = 'true'
    rows = []
    for sample in sample_list:
        t0 = time.time()
        proc = subprocess.run(
            [sys.executable, os.path.join(_ROOT, 'binmind.py'),
             'analyze', sample, '-v'],
            capture_output=True, text=True, timeout=600, env=env,
            # encoding/errors: -v 调试日志含二进制转储字节, 严格解码会抛 UnicodeDecodeError
            encoding='utf-8', errors='replace',
            cwd=_ROOT)
        elapsed = round(time.time() - t0, 2)
        m = re.search(r'Vulnerabilities\s*:\s*(\d+)', proc.stdout)
        vulns = int(m.group(1)) if m else -1
        rows.append((os.path.basename(sample), 'yes' if llm_enabled else 'no',
                     elapsed, vulns, proc.returncode))
    try:
        _need_header = not os.path.exists(_CSV_PATH) or \
            os.path.getsize(_CSV_PATH) == 0
        with open(_CSV_PATH, 'a', newline='', encoding='utf-8') as fh:
            writer = csv.writer(fh)
            if _need_header:
                writer.writerow(['sample', 'llm_enabled', 'elapsed_sec',
                                 'vulns', 'returncode'])
            writer.writerows(rows)
    except OSError as err:
        print(f'[WARN] CSV 写入失败: {err}', file=sys.stderr)
    return rows


if __name__ == '__main__':
    _samples = sys.argv[1:]
    _llm = False
    if '--llm' in _samples:
        _llm = True
        _samples.remove('--llm')
    if not _samples:
        print('[INFO] 用法: python scripts/benchmark.py <sample> [<sample> ...] [--llm]')
        sys.exit(1)
    _result = run_benchmark(_samples, _llm)
    for _row in _result:
        print(_row)
