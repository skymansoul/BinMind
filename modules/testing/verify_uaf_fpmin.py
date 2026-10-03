"""uaf_fpmin 与 baseline 对比验证脚本."""
import os
import subprocess
import sys

PROJ_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, PROJ_ROOT)

from modules.analysis.static.uaf_analysis.binary_uaf_scanner import \
    BinaryUafScanner  # noqa: E402
from modules.analysis.static.uaf_analysis.uaf_fpmin_scanner import \
    UafFpminScanner  # noqa: E402

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "uaf_samples")

print(f"{'sample':<32}{'raw':>5}{'fpmin':>7}{'supp':>6}")
for entry in sorted(os.listdir(BASE)):
    if not (entry.startswith("fp_") or entry.startswith("uaf_")):
        continue
    exe = os.path.join(BASE, entry, "vuln.exe")
    txt = subprocess.run(["objdump", "-d", "-M", "intel", exe],
                         capture_output=True, text=True, errors="ignore",
                         timeout=60).stdout
    raw = BinaryUafScanner().scan(txt, user_code_only=True)
    r = UafFpminScanner(binary_path=exe).scan(txt, user_code_only=True)
    print(f"{entry:<32}{len(raw):>5}{r['n_findings']:>7}"
          f"{r['n_suppressed']:>6}")
    for s in r["suppressed"]:
        print(f"     - [{s['subtype']}] {s['reason'][:110]}")
