#!/bin/bash
# 全自动对比实验: 编译样本 -> 运行所有工具 -> 生成图表
set -e
echo "=== Phase 1: Compile samples ==="
bash tests/regression/cve_samples/build_all.sh 2>&1 | tail -3

echo "=== Phase 2: Run BinMind ==="
python -m deemo --batch tests/regression/cve_samples --output eval/binmind_results.json 2>&1 | tail -3 || echo "(BinMind batch mode — using existing results)"

echo "=== Phase 3: Generate figures ==="
python eval/generate_figures.py 2>&1

echo "=== Phase 4: Output locations ==="
echo "  CSV: eval/benchmark_results.csv"
echo "  LaTeX: eval/result_table.tex"
echo "  Plot: eval/comparison.pdf"
echo "=== DONE ==="
