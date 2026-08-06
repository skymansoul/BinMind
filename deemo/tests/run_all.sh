#!/bin/bash
# 一键回归测试 — 编译 → 扫描 → 统计
# 用法: bash run_all.sh [x86_64|arm|aarch64]
set -e
ARCH=${1:-x86_64}
BASE="$(cd "$(dirname "$0")" && pwd)"
SAMPLES="$BASE/cve_samples"
BUILD="$SAMPLES/build/$ARCH"
RESULTS="$BASE/results"
mkdir -p "$BUILD" "$RESULTS"

echo "=== [1/3] Building CVE samples for $ARCH ==="
count=0
for d in "$SAMPLES"/cve_*/; do
    src="$d/vuln.c"
    [ -f "$src" ] || continue
    name=$(basename "$d")
    out="$BUILD/${name}.elf"
    if gcc -g -O0 -o "$out" "$src" 2>/dev/null; then
        count=$((count+1))
    fi
done
echo "  Built $count samples"

echo "=== [2/3] Running BinMind scanner ==="
cd "$BASE/..";
python -c "
import sys, os, json, time
sys.path.insert(0, '.')
from modules.core.compat.scan_pipeline import run_pipeline_minimal
build_dir = '$BUILD'
results = []
for f in sorted(os.listdir(build_dir)):
    if not f.endswith('.elf'): continue
    path = os.path.join(build_dir, f)
    t0 = time.perf_counter()
    r = run_pipeline_minimal(path)
    wall = (time.perf_counter() - t0) * 1000
    results.append({'sample': f, 'wall_ms': wall, 'findings': r.to_dict()['findings']})
with open('$RESULTS/scan_results.json', 'w') as fh:
    json.dump({'total': len(results), 'results': results}, fh, indent=2)
print(f'  Scanned {len(results)} binaries')
" 2>&1 | tail -3

echo "=== [3/3] Summary ==="
python -c "
import json
with open('$RESULTS/scan_results.json') as f:
    data = json.load(f)
print(f'  Total samples: {data[\"total\"]}')
" 2>/dev/null || echo "  Results in $RESULTS/"
echo "Done."
