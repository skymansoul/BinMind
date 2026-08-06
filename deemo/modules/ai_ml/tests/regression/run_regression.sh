#!/bin/bash
# created: 2026-08-07
# 一键回归测试——编译→扫描→解析汇总
# 用法: bash tests/regression/run_regression.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Step 1/3: 编译样本 ==="
python compile_samples.py
echo ""

echo "=== Step 2/3: 扫描检测 ==="
python scan_runner.py
echo ""

echo "=== Step 3/3: 解析结果 ==="
python result_parser.py
echo ""

echo "回归测试完成。报告: build/report.json"
