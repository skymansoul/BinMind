#!/bin/bash
# 一键回归测试: 编译 → 扫描 → 收集结果
set -e
BASE="$(cd "$(dirname "$0")" && pwd)"
echo "=== Phase 1: Compile ===" && bash "$BASE/cve_samples/build_all.sh" 2>&1 | tail -2
echo "=== Phase 2: Scan ===" && python "$BASE/test_runner.py" 2>&1 | tail -20
echo "=== Phase 3: Results ===" && ls "$BASE/results/" 2>/dev/null && cat "$BASE/results/"*.json 2>/dev/null | python -c "import sys,json; d=json.load(sys.stdin); print(f'Samples: {d.get(\"total\",\"?\")}, Detected: {d.get(\"detected\",\"?\")}')" 2>/dev/null || echo "(run test_runner.py for detailed results)"
echo "=== DONE ==="
