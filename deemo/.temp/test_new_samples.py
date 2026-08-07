"""对新样本运行HOSV检测, 识别FP/FN"""
import sys, json
from pathlib import Path

sys.path.insert(0, str(Path(r"C:\Users\Administrator\Desktop\BinMind\deemo")))

from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier

SAMPLE_DIR = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow")

gt_path = SAMPLE_DIR / "ground_truth.json"
with open(gt_path, encoding="utf-8") as f:
    gt = json.load(f)

new_samples = [k for k in gt["samples"] if k.startswith("cve_4") or k.startswith("cve_5")]
new_samples.sort()

v = HeapOverflowSrcVerifier()

print(f"{'Sample':<45} {'Expected':<6} {'Got':<10} {'Match':<6} {'Details'}")
print("-" * 120)

fp_list = []
fn_list = []
tp_list = []
tn_list = []

for name in new_samples:
    d = SAMPLE_DIR / name
    c_files = list(d.glob("*.c"))
    if not c_files:
        print(f"{name}: NO .c FILE")
        continue

    source = c_files[0].read_text(encoding="utf-8")
    results = v.verify(source)

    expected_vuln = gt["samples"][name]["expected_vuln"]
    got_vuln = any(r.verdict.value == "VULN" for r in results)
    got_safe = any(r.verdict.value == "SAFE" for r in results) and not got_vuln
    got_uncertain = any(r.verdict.value == "UNCERTAIN" for r in results) and not got_vuln

    if got_vuln:
        got_str = "VULN"
    elif got_safe:
        got_str = "SAFE"
    elif got_uncertain:
        got_str = "UNCERTAIN"
    else:
        got_str = "CLEAN"

    match = (expected_vuln == got_vuln)
    match_str = "OK" if match else "FAIL"

    details = ""
    for r in results:
        details += f"[{r.verdict.value}@L{r.write_line}] {r.reason[:60]}; "

    if not match:
        if expected_vuln and not got_vuln:
            fn_list.append(name)
            details = f"** FN ** {details}"
        elif not expected_vuln and got_vuln:
            fp_list.append(name)
            details = f"** FP ** {details}"

    if expected_vuln and got_vuln:
        tp_list.append(name)
    elif not expected_vuln and not got_vuln:
        tn_list.append(name)

    print(f"{name:<45} {'VULN' if expected_vuln else 'SAFE':<6} {got_str:<10} {match_str:<6} {details}")

print("\n" + "=" * 80)
print(f"TP={len(tp_list)}  FP={len(fp_list)}  TN={len(tn_list)}  FN={len(fn_list)}")
if fp_list:
    print(f"FP samples: {fp_list}")
if fn_list:
    print(f"FN samples: {fn_list}")
if not fp_list and not fn_list:
    print("ALL CORRECT!")
