#!/bin/bash
# 回归测试入口 — 三阶段: 编译 → 扫描 → 解析
# 用法: bash tests/regression_test.sh [--timeout 120]

set -e
TIMEOUT=120
if [ "$1" = "--timeout" ] && [ -n "$2" ]; then
    TIMEOUT="$2"
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== Phase 1: Build samples ==="
python tests/build_samples.py

echo ""
echo "=== Phase 2: Scan samples ==="
python tests/run_scanner.py --timeout "$TIMEOUT"

echo ""
echo "=== Phase 3: Parse results ==="
python tests/parse_results.py

echo ""
echo "Regression test complete."
