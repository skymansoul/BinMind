# coding: utf-8
"""
真实 CVE 样本回归 — 对 samples/cve_heap_overflow 运行写模式扩展检测,
输出各样本检出状态与耗时. 期望标注见 cve_truth.json.

仅对标注为 VULN 的样本断言检出, UNKNOWN 样本只报告不判定.
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", ".."))

from analysis.heap_write_ext_verifier import HosvExtVerifier  # noqa: E402

BASE = os.path.dirname(os.path.abspath(__file__))
CVE_SAMPLES = os.path.join(BASE, "..", "..", "samples", "cve_heap_overflow")
TRUTH_P = os.path.join(BASE, "cve_truth.json")


def load_truth():
    with open(TRUTH_P, "r", encoding="utf-8") as f:
        return json.load(f)


def run():
    truth = load_truth()
    v = HosvExtVerifier()
    print("%-32s %-8s %-8s %8s %s" % ("sample", "expected", "actual",
                                       "time_ms", "modes"))
    print("-" * 90)
    tp = fp = fn = unk = 0
    for d in sorted(os.listdir(CVE_SAMPLES)):
        dd = os.path.join(CVE_SAMPLES, d)
        if not os.path.isdir(dd):
            continue
        cf = [f for f in os.listdir(dd) if f.endswith(".c")]
        if not cf:
            continue
        src = open(os.path.join(dd, cf[0]), encoding="utf-8",
                   errors="replace").read()
        t0 = time.time()
        res = v.verify(src)
        dt = (time.time() - t0) * 1000
        vulns = [o for o in res if o.verdict == "VULN"]
        modes = ",".join(sorted({o.kind for o in vulns})) or "-"
        exp = truth.get(d, {}).get("expected", "UNKNOWN")
        actual = "VULN" if vulns else "none"
        print("%-32s %-8s %-8s %8.1f %s" % (d, exp, actual, dt, modes))
        if exp == "VULN":
            if vulns:
                tp += 1
            else:
                fn += 1
        elif exp == "UNKNOWN":
            unk += 1
        else:
            if vulns:
                fp += 1
    print("-" * 90)
    print("TP=%d FN=%d FP=%d UNKNOWN=%d" % (tp, fn, fp, unk))
    return tp, fn, fp


if __name__ == "__main__":
    run()
