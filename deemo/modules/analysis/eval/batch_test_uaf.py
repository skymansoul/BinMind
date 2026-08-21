# UAF批量测试脚本 v1 - 对UAF样本执行BinMind检测并输出统一结果
# 支持: CVE样本 (benchmark/samples_uaf/) + FP-safe样本 (benchmark/samples_uaf_safe/)
# 多优化级: O0/O2/Os

import sys, os, json, time, subprocess, csv, argparse
try:
    import resource
except ImportError:
    resource = None  # Windows fallback
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional

BASE = Path(__file__).resolve().parents[1]
EVAL_DIR = Path(__file__).resolve().parent
RESULTS_DIR = EVAL_DIR / "results_uaf"
RESULTS_DIR.mkdir(exist_ok=True)

_PROJECT_ROOT = BASE.parent.parent  # deemo/
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# 样本目录
CVE_SAMPLES_DIR = BASE / "benchmark" / "samples_uaf"
FP_SAFE_DIR = BASE / "benchmark" / "samples_uaf_safe"
REGRESSION_SAMPLES_DIR = BASE / "tests" / "regression" / "samples"


def _disassemble(binary_path: str) -> List[dict]:
    """objdump反汇编 → 结构化指令列表."""
    try:
        out = subprocess.run(
            ["objdump", "-d", "-M", "intel", binary_path],
            capture_output=True, text=True, timeout=30
        ).stdout
    except Exception:
        return []

    insns = []
    for line in out.split("\n"):
        parts = line.strip().split("\t")
        if len(parts) < 3:
            continue
        try:
            addr = int(parts[0].strip().rstrip(":"), 16)
            mnem_part = parts[2].split()
            mnem = mnem_part[0] if mnem_part else ""
            ops = []
            if len(mnem_part) > 1:
                for o in " ".join(mnem_part[1:]).split(","):
                    ops.append(o.strip())
            insns.append({"address": addr, "mnemonic": mnem, "operands": ops})
        except (ValueError, IndexError):
            continue
    return insns


def run_uaf_detection(binary_path: str) -> dict:
    """对单个二进制运行UAF检测."""
    t0 = time.perf_counter()
    result = {"tool": "BinMind-UAF", "binary": binary_path,
              "detected": False, "finding_count": 0,
              "uaf_count": 0, "double_free_count": 0,
              "time_ms": 0, "findings": [], "error": ""}

    from modules.analysis.static.disasm_util import disassemble_binary
    instructions, _fmt, _main, user_ranges = disassemble_binary(binary_path)
    if not instructions:
        result["error"] = "disassembly failed"
        result["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return result

    try:
        from modules.analysis.static.uaf_detect import UAFDetector

        detector = UAFDetector(use_win64_abi=True)

        if user_ranges:
            detector.set_user_func_ranges(user_ranges)
        detector.pre_analyze(instructions)

        for ins in instructions:
            detector.analyze_instruction(ins)

        findings = detector.finalize(instructions)
        uaf = [f for f in findings if f.get("type") == "use_after_free"]
        df = [f for f in findings if f.get("type") == "double_free"]

        result["findings"] = findings
        result["finding_count"] = len(findings)
        result["uaf_count"] = len(uaf)
        result["double_free_count"] = len(df)
        result["detected"] = len(findings) > 0
        result["stats"] = detector.stats()

    except Exception as e:
        result["error"] = str(e)[:200]

    result["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return result


def compile_and_test(source_path: str, binary_path: str, opt: str = "O0") -> dict:
    """编译单个C源文件并测试."""
    # 编译
    cc = "x86_64-w64-mingw32-gcc"
    cmd = [cc, f"-{opt}", "-no-pie", "-fno-stack-protector",
           "-fno-asynchronous-unwind-tables", "-w",
           "-o", binary_path, source_path]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return {"tool": "BinMind-UAF", "binary": binary_path,
                "detected": False, "finding_count": 0,
                "time_ms": 0, "error": f"compile failed: {r.stderr[:100]}"}

    return run_uaf_detection(binary_path)


def test_cve_samples(opts: List[str] = None) -> List[dict]:
    """测试所有CVE UAF样本."""
    if opts is None:
        opts = ["O0"]

    results = []
    cve_dirs = sorted(d for d in CVE_SAMPLES_DIR.iterdir() if d.is_dir())

    for cve_dir in cve_dirs:
        c_files = list(cve_dir.glob("*.c"))
        if not c_files:
            continue

        cve_name = cve_dir.name
        for opt in opts:
            binary = str(BUILD_TMP / f"{cve_name}_{opt}.exe")
            r = compile_and_test(str(c_files[0]), binary, opt)
            r["cve"] = cve_name
            r["opt"] = opt
            r["sample_type"] = "cve"
            results.append(r)

    return results


def test_fp_safe_samples(opts: List[str] = None) -> List[dict]:
    """测试FP-safe UAF样本 (从manifest)."""
    if opts is None:
        opts = ["O0", "O2", "Os"]

    manifest_path = FP_SAFE_DIR / "manifest.json"
    results = []

    if manifest_path.exists():
        with open(manifest_path) as f:
            manifest = json.load(f)

        for entry in manifest:
            binary = entry["binary"]
            opt = entry["opt"]
            if opt not in opts:
                continue

            if os.path.exists(binary):
                r = run_uaf_detection(binary)
            else:
                # 尝试编译
                src = entry["source"]
                r = compile_and_test(src, binary, opt)

            r["pattern"] = entry["pattern"]
            r["variant"] = entry["variant"]
            r["opt"] = opt
            r["expected"] = entry.get("expected", "unknown")
            r["sample_type"] = "fp_safe"
            results.append(r)

    return results


def test_regression_samples(opts: List[str] = None) -> List[dict]:
    """测试回归样本目录中的UAF样本."""
    if opts is None:
        opts = ["O0"]

    results = []
    uaf_dirs = sorted(d for d in REGRESSION_SAMPLES_DIR.iterdir()
                      if d.is_dir() and "uaf" in d.name.lower())

    for sample_dir in uaf_dirs:
        c_files = list(sample_dir.glob("*.c"))
        if not c_files:
            continue

        for opt in opts:
            binary = str(BUILD_TMP / f"reg_{sample_dir.name}_{opt}.exe")
            r = compile_and_test(str(c_files[0]), binary, opt)
            r["cve"] = sample_dir.name
            r["opt"] = opt
            r["sample_type"] = "regression"
            results.append(r)

    return results


def compute_metrics(results: List[dict]) -> dict:
    """从结果计算TP/FP/TN/FN/F1."""
    metrics = {"total": len(results),
               "TP": 0, "FP": 0, "TN": 0, "FN": 0}

    for r in results:
        detected = r.get("detected", False)
        expected = r.get("expected", "")

        if expected == "UAF" or r.get("variant") == "vuln":
            if detected:
                metrics["TP"] += 1
            else:
                metrics["FN"] += 1
        elif expected == "SAFE" or r.get("variant") == "safe":
            if detected:
                metrics["FP"] += 1
            else:
                metrics["TN"] += 1
        else:
            # CVE样本: 应该检出
            if detected:
                metrics["TP"] += 1
            else:
                metrics["FN"] += 1

    tp, fp, tn, fn = metrics["TP"], metrics["FP"], metrics["TN"], metrics["FN"]
    total = tp + fp + tn + fn
    metrics["recall"] = tp / max(1, tp + fn)
    metrics["precision"] = tp / max(1, tp + fp)
    metrics["fpr"] = fp / max(1, fp + tn) if fp + tn > 0 else 0.0
    metrics["f1"] = (2 * metrics["precision"] * metrics["recall"] /
                     max(1, metrics["precision"] + metrics["recall"]))

    return metrics


def print_report(results: List[dict], metrics: dict):
    """打印测试报告."""
    print(f"\n{'='*70}")
    print(f"UAF Detection Benchmark Report")
    print(f"{'='*70}")
    print(f"Total samples: {metrics['total']}")
    print(f"  TP={metrics['TP']}, FP={metrics['FP']}, "
          f"TN={metrics['TN']}, FN={metrics['FN']}")
    print(f"  Recall:    {metrics['recall']:.1%}")
    print(f"  Precision: {metrics['precision']:.1%}")
    print(f"  FPR:       {metrics['fpr']:.1%}")
    print(f"  F1:        {metrics['f1']:.4f}")

    # 分组统计
    by_type = defaultdict(list)
    for r in results:
        by_type[r.get("sample_type", "unknown")].append(r)

    for stype, sresults in by_type.items():
        sm = compute_metrics(sresults)
        print(f"\n  [{stype}] n={sm['total']}: "
              f"R={sm['recall']:.1%} P={sm['precision']:.1%} "
              f"FPR={sm['fpr']:.1%} F1={sm['f1']:.4f}")

    # FP详情
    fps = [r for r in results if r.get("variant") == "safe" and r.get("detected")]
    if fps:
        print(f"\n  FP details ({len(fps)}):")
        for r in fps:
            print(f"    {r.get('pattern','?'):20s} {r.get('opt','?'):3s}: "
                  f"{r.get('finding_count',0)} findings")

    # FN详情
    fns = [r for r in results if (r.get("variant") == "vuln" or r.get("sample_type") in ("cve", "regression"))
           and not r.get("detected")]
    if fns:
        print(f"\n  FN details ({len(fns)}):")
        for r in fns:
            print(f"    {r.get('pattern',r.get('cve','?')):30s} {r.get('opt','?'):3s}: "
                  f"error={r.get('error','')[:60]}")


BUILD_TMP = EVAL_DIR / "build_tmp_uaf"
BUILD_TMP.mkdir(exist_ok=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="UAF批量测试")
    p.add_argument("--cve", action="store_true", help="测试CVE样本")
    p.add_argument("--fp-safe", action="store_true", help="测试FP-safe样本")
    p.add_argument("--regression", action="store_true", help="测试回归样本")
    p.add_argument("--all", action="store_true", help="测试全部")
    p.add_argument("--opts", default="O0", help="优化级, 逗号分隔 (O0,O2,Os)")
    p.add_argument("--json", action="store_true", help="JSON输出")
    args = p.parse_args()

    opts = [o.strip() for o in args.opts.split(",")]

    all_results = []

    if args.all or args.cve:
        print("Testing CVE UAF samples...")
        cve_results = test_cve_samples(opts)
        all_results.extend(cve_results)
        for r in cve_results:
            status = "DETECT" if r["detected"] else "CLEAN "
            err = f" ERR:{r['error'][:40]}" if r.get("error") else ""
            print(f"  {r['cve'][:40]:40s} {r['opt']:3s}: {status} "
                  f"uaf={r.get('uaf_count',0)} df={r.get('double_free_count',0)} "
                  f"{r['time_ms']:.0f}ms{err}")

    if args.all or args.fp_safe:
        print("\nTesting FP-safe UAF samples...")
        fp_results = test_fp_safe_samples(opts)
        all_results.extend(fp_results)
        for r in fp_results:
            status = "DETECT" if r["detected"] else "CLEAN "
            expected = r.get("expected", "?")
            match = "OK" if (r["detected"] and expected == "UAF") or \
                          (not r["detected"] and expected == "SAFE") else "XX"
            err = f" ERR:{r['error'][:40]}" if r.get("error") else ""
            print(f"  {match} {r.get('pattern','?'):25s} {r.get('variant','?'):5s} "
                  f"{r['opt']:3s}: {status} {r.get('finding_count',0)}f "
                  f"{r['time_ms']:.0f}ms{err}")

    if args.all or args.regression:
        print("\nTesting regression UAF samples...")
        reg_results = test_regression_samples(opts)
        all_results.extend(reg_results)
        for r in reg_results:
            status = "DETECT" if r["detected"] else "CLEAN "
            print(f"  {r['cve'][:40]:40s} {r['opt']:3s}: {status} "
                  f"{r.get('finding_count',0)}f {r['time_ms']:.0f}ms")

    if all_results:
        metrics = compute_metrics(all_results)
        print_report(all_results, metrics)

        # 保存结果
        json_path = RESULTS_DIR / "uaf_benchmark_results.json"
        with open(json_path, "w") as f:
            json.dump({"results": all_results, "metrics": metrics}, f,
                      indent=2, default=str)

        if args.json:
            print(json.dumps({"results": all_results, "metrics": metrics},
                            indent=2, default=str))
    else:
        print("No tests selected. Use --cve, --fp-safe, --regression, or --all")
