"""评估扫描结果: 统计源码级+二进制级检出率/漏报率/误报率。"""
import json, os
RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_results.json")
if not os.path.isfile(RESULTS): print("No scan results. Run run_scan.py first."); exit(1)
with open(RESULTS) as f: scan = json.load(f)

# 源码级结果
src_results = [r for r in scan if r.get('method') == 'source-level']
total_src = len(src_results)
total_findings = sum(r.get('source_scan',{}).get('total',0) for r in src_results)
uaf_f = sum(r.get('source_scan',{}).get('uaf',0) for r in src_results)
io_f = sum(r.get('source_scan',{}).get('int_overflow',0) for r in src_results)
heap_f = sum(r.get('source_scan',{}).get('heap_bounds',0) for r in src_results)

# 二进制结果
bin_results = [r for r in scan if r.get('method') == 'binary-main']
total_bin = len(bin_results)
bin_findings = sum(r.get('binary_findings',0) for r in bin_results)

stats = {"source_scans": total_src, "binary_scans": total_bin,
         "source_findings": {"total": total_findings, "uaf": uaf_f, "int_overflow": io_f, "heap_bounds": heap_f},
         "binary_findings": bin_findings}
out_path = RESULTS.replace(".json", "_eval.json")
with open(out_path, "w") as f: json.dump(stats, f, indent=2)
print(f"Source: {total_src} scans, {total_findings} findings (UAF={uaf_f}, IntOvf={io_f}, Heap={heap_f})")
print(f"Binary: {total_bin} scans, {bin_findings} findings")
print(f"Saved: {out_path}")
