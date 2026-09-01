"""汇总打印 tests/scan_results 下的扫描结果 JSON。

TP/FP 堆样本与真实 CVE 样本分开三批展示，单条含检测数、
TP/FP/不确定计数与相位贡献，加载失败仅标记不中断。
"""
import json, glob, os

def dump(pattern, label):
    print(f"=== {label} ===")
    files = sorted(glob.glob(pattern))
    for f in files:
        try:
            d = json.load(open(f, encoding='utf-8'))
        except Exception as e:
            print(f"  {os.path.basename(f):55s} LOAD_ERR {e}")
            continue
        print(f"  {d.get('sample', '?')[:50]:52s} det={d.get('detected')} "
              f"tp={d.get('tp_count')} fp={d.get('fp_count')} "
              f"unc={d.get('uncertain_count')} err={d.get('error')}")
        pc = d.get('phase_contributions') or {}
        if pc:
            print(f"      phases={pc}")

dump(r'tests/scan_results/CVE-2025-TP*.json', "TP heap samples")
dump(r'tests/scan_results/CVE-2025-FP*.json', "FP heap samples")
dump(r'tests/scan_results/CVE-20*-*.json', "Real CVE samples")
