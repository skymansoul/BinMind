#!/usr/bin/env python
"""tests/regression/run_validation.py — 一键验证管线: 对所有编译样本运行 AC3 v1 和 路径敏感值域推理-HLM v2。
从 modules/info 目录运行: python tests/regression/run_validation.py"""

import sys, os, json, time, subprocess, csv, tracemalloc
from pathlib import Path

# 确保包导入正确
_PROJ = Path(__file__).parent.parent.parent  # modules/info
sys.path.insert(0, str(_PROJ))
sys.path.insert(0, str(_PROJ / "analysis"))
sys.path.insert(0, str(_PROJ / "info_collection"))
sys.path.insert(0, str(_PROJ / "info_collection" / "src"))

SAMPLES_DIR = Path(__file__).parent / "samples"
GT_FILE = Path(__file__).parent / "ground_truth.json"
OUT_CSV = Path(__file__).parent / "validation_results.csv"
OUT_JSON = Path(__file__).parent / "validation_results.json"


def load_ground_truth():
    if not GT_FILE.exists():
        return {}
    with open(GT_FILE) as f:
        data = json.load(f)
    return data.get("samples", {})


def find_binary(sample_dir: Path):
    for name in ("vuln.exe", "vuln", "vuln.elf"):
        p = sample_dir / name
        if p.is_file():
            return p
    for ext in (".exe", ".elf", ""):
        elfs = list(sample_dir.glob(f"vuln*{ext}"))
        if elfs:
            return elfs[0]
    return None


def extract_imports(target: str) -> dict:
    imports = {"all_imports": {}}
    try:
        proc = subprocess.run(["objdump", "-T", str(target)],
                              capture_output=True, text=True, timeout=10)
        for line in proc.stdout.splitlines():
            if "*UND*" in line:
                parts = line.split()
                if len(parts) >= 5:
                    imports["all_imports"].setdefault("libc.so.6", []).append(parts[-1])
    except Exception:
        pass
    return imports


def extract_strings(target: str):
    try:
        proc = subprocess.run(["strings", str(target)],
                              capture_output=True, text=True, timeout=10)
        return [(i, s) for i, s in enumerate(proc.stdout.splitlines()) if len(s) >= 3]
    except Exception:
        return []


def get_checksec(target: str) -> dict:
    try:
        proc = subprocess.run(["objdump", "-f", str(target)],
                              capture_output=True, text=True, timeout=5)
        out = proc.stdout
        return {"arch": "i386" if "elf32" in out.lower() else "x86_64"}
    except Exception:
        return {"arch": "x86_64"}


def run_ac3_v1(target: str, sample_dir: Path):
    """AC3 v1: 通过子进程调用避免相对导入问题。"""
    t0 = time.time()
    try:
        runner = _PROJ / "tests" / "_run_ac3_v1.py"
        # 确保 runner 存在
        if not runner.exists():
            _write_runner(runner)
        proc = subprocess.run(
            [sys.executable, str(runner), str(target), str(sample_dir)],
            capture_output=True, text=True, timeout=30, cwd=str(_PROJ))
        if proc.returncode == 0:
            data = json.loads(proc.stdout.strip())
        else:
            data = {"error": proc.stderr[:200]}
        elapsed = round((time.time() - t0) * 1000, 1)
        data["elapsed_ms"] = elapsed
        data["tool"] = "AC3-v1"
        return data
    except Exception as e:
        return {"tool": "AC3-v1", "findings": 0, "elapsed_ms": 0, "error": str(e)[:100]}


def run_v2(target: str, sample_dir: Path):
    """路径敏感值域推理-HLM v2"""
    t0 = time.time()
    try:
        from heap_overflow_v2 import detect_heap_overflow_v2

        imports = extract_imports(target)
        strings = extract_strings(target)
        checksec = get_checksec(target)

        code = ""
        src = sample_dir / "vuln.c"
        if src.exists():
            code = src.read_text(encoding="utf-8", errors="replace")

        result = detect_heap_overflow_v2(code=code, imports=imports,
                                          strings=strings, checksec=checksec)
        stats = result.get("stats", {})
        vra = result.get("vra_stats", {})
        elapsed = round((time.time() - t0) * 1000, 1)

        return {"tool": "PSVR-HLM-v2",
                "findings": stats.get("total", 0),
                "high_conf": stats.get("high_conf", 0),
                "vra_safe_filtered": vra.get("definitely_safe", 0),
                "fp_reduction_pct": result.get("fp_reduction_pct", 0),
                "avg_confidence": stats.get("avg_confidence", 0),
                "elapsed_ms": elapsed, "error": None}
    except Exception as e:
        return {"tool": "PSVR-HLM-v2", "findings": 0, "elapsed_ms": 0,
                "error": str(e)[:100]}


def _write_runner(path: Path):
    """生成 AC3 v1 子进程调用器"""
    path.write_text(r'''#!/usr/bin/env python
import sys, json; target = sys.argv[1]; sample_dir = sys.argv[2]
sys.path.insert(0, "."); sys.path.insert(0, "info_collection"); sys.path.insert(0, "info_collection/src")
import subprocess
# 提取导入
imports = {"all_imports": {}}
try:
    p = subprocess.run(["objdump", "-T", target], capture_output=True, text=True, timeout=10)
    for line in p.stdout.splitlines():
        if "*UND*" in line:
            parts = line.split()
            if len(parts) >= 5:
                imports["all_imports"].setdefault("libc.so.6", []).append(parts[-1])
except: pass
# 提取字符串
try:
    p = subprocess.run(["strings", target], capture_output=True, text=True, timeout=10)
    strings = [(i, s) for i, s in enumerate(p.stdout.splitlines()) if len(s) >= 3]
except: strings = []
# checksec
checksec = {"arch": "x86_64"}
# AC3检测
from info_collection.src.heap_overflow_detector import detect_heap_overflow
result = detect_heap_overflow(imports, strings, checksec)
stats = result.get("stats", {})
out = {"findings": stats.get("total", 0), "high_conf": stats.get("high_conf", 0),
       "avg_confidence": stats.get("avg_confidence", 0)}
print(json.dumps(out))
''')


def main():
    gt = load_ground_truth()
    target_dirs = sorted(
        d for d in SAMPLES_DIR.iterdir()
        if d.is_dir() and ("CVE-2024-" in d.name or d.name.startswith("NEG-"))
    )
    print(f"Target samples: {len(target_dirs)}")
    print(f"Ground truth entries: {len(gt)}")

    results = []
    stats_v1 = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    stats_v2 = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}

    for d in target_dirs:
        elf = find_binary(d)
        if not elf:
            print(f"  SKIP {d.name}: no binary")
            continue

        sample_gt = gt.get(d.name, {})
        is_vuln = sample_gt.get("is_vulnerable", None)
        vt = sample_gt.get("vulnerability_type", "unknown")
        print(f"\n{'='*60}")
        print(f"Sample: {d.name}  |  GT: is_vuln={is_vuln}  type={vt}")

# AC3 v1
        r1 = run_ac3_v1(str(elf), d)
        findings1 = r1.get("findings", 0)
        detected1 = findings1 > 0
        if is_vuln is True:
            r1["status"] = "TP" if detected1 else "FN"
            stats_v1["TP" if detected1 else "FN"] += 1
        elif is_vuln is False:
            r1["status"] = "FP" if detected1 else "TN"
            stats_v1["FP" if detected1 else "TN"] += 1
        else:
            r1["status"] = "UNKNOWN"
        r1["sample"] = d.name
        r1["is_vulnerable"] = is_vuln
        results.append(r1)
        print(f"  AC3-v1:        findings={findings1}, status={r1['status']}, "
              f"{r1.get('elapsed_ms', 0):.0f}ms")

# 路径敏感值域推理-HLM v2
        r2 = run_v2(str(elf), d)
        findings2 = r2.get("findings", 0)
        detected2 = findings2 > 0
        if is_vuln is True:
            r2["status"] = "TP" if detected2 else "FN"
            stats_v2["TP" if detected2 else "FN"] += 1
        elif is_vuln is False:
            r2["status"] = "FP" if detected2 else "TN"
            stats_v2["FP" if detected2 else "TN"] += 1
        else:
            r2["status"] = "UNKNOWN"
        r2["sample"] = d.name
        r2["is_vulnerable"] = is_vuln
        results.append(r2)
        print(f"  PSVR-HLM-v2:   findings={findings2}, status={r2['status']}, "
              f"FP_reduction={r2.get('fp_reduction_pct',0)}%, "
              f"{r2.get('elapsed_ms', 0):.0f}ms")

    # 汇总
    def compute_metrics(stats):
        tp, fp, tn, fn = stats["TP"], stats["FP"], stats["TN"], stats["FN"]
        recall = tp / max(tp + fn, 1)
        precision = tp / max(tp + fp, 1)
        fpr = fp / max(fp + tn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 0.01)
        return recall, precision, fpr, f1

    print(f"\n{'='*60}")
    print("FINAL COMPARISON")
    print(f"{'='*60}")
    r1, p1, fpr1, f11 = compute_metrics(stats_v1)
    r2, p2, fpr2, f12 = compute_metrics(stats_v2)
    print(f"AC3-v1:       TP={stats_v1['TP']} FP={stats_v1['FP']} "
          f"TN={stats_v1['TN']} FN={stats_v1['FN']}")
    print(f"  Recall={r1*100:.1f}%  Precision={p1*100:.1f}%  "
          f"FP_Rate={fpr1*100:.1f}%  F1={f11:.3f}")
    print(f"PSVR-HLM-v2:  TP={stats_v2['TP']} FP={stats_v2['FP']} "
          f"TN={stats_v2['TN']} FN={stats_v2['FN']}")
    print(f"  Recall={r2*100:.1f}%  Precision={p2*100:.1f}%  "
          f"FP_Rate={fpr2*100:.1f}%  F1={f12:.3f}")

    fp_reduction = (fpr1 - fpr2) / max(fpr1, 0.01) * 100 if fpr1 > 0 else 0
    print(f"\n>>> FP Reduction: {fp_reduction:.1f}%  "
          f"(target: >40%, actual FP_rate: {fpr2*100:.1f}%, "
          f"target: <20%)")
    # 审计口径: SATURATED 为本运行小集的饱和判定输出, 非对外指标宣称
    print(f">>> {'SATURATED ✓' if fpr2 < 0.20 and fp_reduction > 40 else 'NEED ITERATION →'}")

    # 导出
    summary = [
        {"Tool": "AC3-v1", **stats_v1, "Recall": round(r1*100,1),
         "Precision": round(p1*100,1), "FP_Rate": round(fpr1*100,1),
         "F1": round(f11, 3)},
        {"Tool": "PSVR-HLM-v2", **stats_v2, "Recall": round(r2*100,1),
         "Precision": round(p2*100,1), "FP_Rate": round(fpr2*100,1),
         "F1": round(f12, 3)},
    ]
    with open(OUT_JSON, "w") as f:
        json.dump({"summary": summary, "details": results,
                   "timestamp": __import__("datetime").datetime.now().isoformat()},
                  f, indent=2, ensure_ascii=False, default=str)
    print(f"\nResults: {OUT_JSON}")

    # 更新 ground_truth 记录
    return summary, fp_reduction, fpr2


if __name__ == "__main__":
    main()
