"""批量编译+扫描所有42个CVE样本，生成汇总报告"""
import subprocess, json, time, os
from pathlib import Path

BASE = Path(__file__).parent.parent.parent
SAMPLES = BASE / "tests" / "regression" / "samples"
BUILD = BASE / "tests" / "regression" / "build"
FILTER = BASE / "tests" / "regression" / "run_heap_filter.py"
BUILD.mkdir(exist_ok=True)

results = []
for d in sorted(SAMPLES.iterdir()):
    if not d.is_dir(): continue
    vc = d / "vuln.c"
    if not vc.exists(): continue
    name = d.name
    out = BUILD / f"{name}_O0.exe"
    r = subprocess.run(["gcc", "-O0", "-o", str(out), str(vc), "-w"],
                      capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        results.append({"name": name, "status": "COMPILE_FAILED"})
        print(f"  FAIL {name}")
        continue
    try:
        r2 = subprocess.run(["python", str(FILTER), str(out)],
                          capture_output=True, text=True, timeout=30)
        data = json.loads(r2.stdout) if r2.stdout.strip().startswith('{') else {}
        results.append({"name": name, "status": "OK",
                       "sinks": data.get("total_sinks", 0),
                       "confirmed": data.get("confirmed", 0),
                       "filtered": data.get("filtered", 0)})
        print(f"  OK {name}: {data.get('total_sinks',0)} sinks, {data.get('confirmed',0)} conf")
    except Exception as e:
        results.append({"name": name, "status": "SCAN_FAILED"})
        print(f"  SCAN_FAIL {name}")

compiled = sum(1 for r in results if r["status"] == "OK")
total_sinks = sum(r.get("sinks", 0) for r in results)
total_conf = sum(r.get("confirmed", 0) for r in results)
print(f"\n=== SUMMARY ===")
print(f"Compiled: {compiled}/{len(results)}")
print(f"Sinks: {total_sinks}, Confirmed: {total_conf}")

with open(BUILD / "batch_results.json", "w") as f:
    json.dump({"compiled": compiled, "total": len(results),
              "sinks": total_sinks, "confirmed": total_conf,
              "fp_reduction": total_sinks > 0 and (total_sinks - total_conf) / total_sinks or 0}, f)
print("Saved to batch_results.json")
