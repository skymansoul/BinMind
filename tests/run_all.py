# tests/run_all.py - Unified test runner for all vulnerability classes.
# Run: python tests/run_all.py
import os, sys, json, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from collections import defaultdict
from core.heap_fp_filter import HeapFPFilter
from core.taint_propagator import TaintPropagator
from core.lifetime_tracker import LifetimeTracker
from core.uaf_cross_function import UAFCrossFunctionDetector

def load_src(path):
    try:
        with open(path, encoding="utf-8") as f: return f.read()
    except: return None

def test_heap():
    results = []
    for d in sorted(os.listdir("tests/cve_samples_heap")):
        src = os.path.join("tests/cve_samples_heap", d, "vuln.c")
        c = load_src(src)
        if c is None: continue
        r = HeapFPFilter().filter(c)
        gt = d.startswith("CVE")
        detected = r["true_overflows"] > 0
        results.append({"type":"heap","sample":d,"gt":gt,"detected":detected})
    return results

def test_fmt():
    results = []
    for d in sorted(os.listdir("tests/cve_samples")):
        if "format_string" not in d: continue
        src = os.path.join("tests/cve_samples", d, "vuln.c")
        c = load_src(src)
        if c is None: continue
        paths = TaintPropagator().propagate(c)
        fmt = sum(1 for p in paths if p.sink_type=="FORMAT")
        results.append({"type":"fmt","sample":d,"gt":True,"detected":fmt>0})
    return results

def test_uaf():
    results = []
    for d in sorted(os.listdir("tests/cve_samples_uaf")):
        src = os.path.join("tests/cve_samples_uaf", d, "vuln.c")
        c = load_src(src)
        if c is None: continue
        lcs = LifetimeTracker().track(c)
        sites = UAFCrossFunctionDetector().detect(c)
        risk = sum(1 for lc in lcs if lc.has_uaf_risk)
        cross = len(sites) > 0
        gt = d.startswith("CVE") or d.startswith("uaf")
        detected = risk > 0 or cross
        results.append({"type":"uaf","sample":d,"gt":gt,"detected":detected})
    return results


def test_int_overflow():
    from core.integer_overflow_detector import IntegerOverflowDetector
    iod = IntegerOverflowDetector()
    results = []
    for d in sorted(os.listdir("tests/cve_samples_int_overflow")):
        src = os.path.join("tests/cve_samples_int_overflow", d, "vuln.c")
        c = load_src(src)
        if c is None: continue
        sites = iod.detect(c)
        gt = d.startswith("CVE") or d.startswith("int_ovf")
        high = sum(1 for s in sites if s.confidence >= 0.5)
        detected = high > 0
        results.append({"type":"int_overflow","sample":d,"gt":gt,"detected":detected})
    return results

def metrics(all_r):
    bt = defaultdict(lambda: {"tp":0,"fn":0,"fp":0,"tn":0})
    for r in all_r:
        t = bt[r["type"]]
        if r["gt"] and r["detected"]: t["tp"] += 1
        elif r["gt"] and not r["detected"]: t["fn"] += 1
        elif not r["gt"] and r["detected"]: t["fp"] += 1
        else: t["tn"] += 1
    return dict(bt)

if __name__ == "__main__":
    t0 = time.perf_counter()
    all_r = test_heap() + test_fmt() + test_uaf() + test_int_overflow()
    m = metrics(all_r)
    print(json.dumps(m, indent=2))
    for vt, mt in m.items():
        rec = mt["tp"]/max(mt["tp"]+mt["fn"],1)
        fpr = mt["fp"]/max(mt["fp"]+mt["tn"],1)
        print(f"{vt}: recall={rec:.1%} fp={fpr:.1%}")
    print(f"Total: {len(all_r)} samples in {time.perf_counter()-t0:.1f}s")