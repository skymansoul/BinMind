#!/bin/bash
# 一键回归测试: 编译样本 → 扫描 → 汇总报告
# 用法: bash run_regression.sh [--quick]
#   --quick: 仅用gcc O0编译, 跳过clang和O2

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

QUICK_MODE=false
if [ "$1" = "--quick" ]; then QUICK_MODE=true; fi

echo "=== Step 1: Build samples ==="
python build_samples.py
echo ""

echo "=== Step 2: Run scanner ==="
python scan_runner.py
echo ""

echo "=== Step 3: Parse results ==="
python -c "
from result_parser import ResultParser
import json, glob, os

# Load ground truth
gt = {}
for d in sorted(os.listdir('samples')):
    readme = os.path.join('samples', d, 'README.md')
    if os.path.isfile(readme):
        with open(readme) as f:
            content = f.read()
        cve = 'unknown'; vtype = 'unknown'
        for line in content.split('\n'):
            if 'CVE-' in line: cve = line.split('CVE-')[1].split()[0].strip(':'); cve = 'CVE-'+cve
            if 'Type:' in line: vtype = line.split('Type:')[1].strip()
        gt[d] = {'cve_id': cve, 'vuln_type': vtype, 'vuln_count': 1}

parser = ResultParser(gt)
# Collect scan results (from scan_runner output or direct import)
try:
    from scan_runner import ScanRunner
    runner = ScanRunner()
    if os.path.isdir('binaries'):
        scan_results = runner.scan_directory('binaries')
        parsed = parser.parse([{'sample_name': r.sample_name,
                                'findings': r.findings} for r in scan_results])
        print(parser.summary(parsed))
        parser.to_json(parsed, 'results.json')
        print(f'\\nResults saved to results.json')
    else:
        print('No binaries/ directory found. Run build_samples.py first.')
except Exception as e:
    print(f'Error: {e}')
"
echo ""
echo "=== Done ==="
