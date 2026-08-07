#!/usr/bin/env python
"""tests/regression/run_unified_test.py — 统一回归测试: 覆盖全部漏洞类型
对每种漏洞类型的样本运行对应的检测器, 收集统一的 TP/FP/TN/FN 指标。
支持: heap_overflow / stack_overflow / int_overflow / uaf / format_string / double_free
"""

import sys, os, json, time, re
from pathlib import Path
from collections import defaultdict

_PROJ = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_PROJ))
sys.path.insert(0, str(_PROJ / "analysis"))
sys.path.insert(0, str(_PROJ / "info_collection"))
sys.path.insert(0, str(_PROJ / "info_collection" / "src"))

SAMPLES_DIR = Path(__file__).parent / "samples"
GT_FILE = Path(__file__).parent / "ground_truth.json"
RESULTS_FILE = Path(__file__).parent / "unified_test_results.json"

# 漏洞类型 → (检测器模块, 检测函数, 关键词)
DETECTORS = {
    "heap_overflow": ("heap_overflow_v2", "detect_heap_overflow_v2", {}),
    "stack_overflow": ("stack_overflow_v3", "detect_stack_overflow_v3", {}),
    "int_overflow": ("int_overflow_v3", "detect_int_overflow_v3", {}),
    "uaf": ("uaf_lifecycle", "detect_uaf_v3", {}),
    "format_string": ("format_string_v3", "detect_format_string_v3", {}),
    "double_free": ("double_free_analyzer", "detect_double_free", {}),
}


def classify_sample(name: str) -> str:
    """根据样本目录名推断漏洞类型。"""
    n = name.lower()
    # NEG 样本: 检查关键词推断类型
    if name.startswith("NEG-"):
        if any(k in n for k in ("heap", "malloc", "calloc", "realloc", "memcpy",
                                  "overflow", "alloc", "sizeof", "fortify", "guard")):
            return "heap_overflow"
        if "stack" in n: return "stack_overflow"
        if "fmt" in n or "format" in n: return "format_string"
        if "uaf" in n: return "uaf"
        if "int" in n: return "int_overflow"
        return "heap_overflow"  # 默认归类为 heap
    # CVE 样本
    if "heartbleed" in n or "ghost" in n:
        return "heap_overflow"  # Heartbleed/Ghost 都是堆相关
    if "realloc_misuse" in n or "malloc_memcpy" in n:
        return "heap_overflow"
    if "stack" in n:
        return "stack_overflow"
    if "heap" in n or ("overflow" in n and "stack" not in n and "int" not in n):
        return "heap_overflow"
    if "int_overflow" in n or "integer" in n or "_int_" in n:
        return "int_overflow"
    if "uaf" in n:
        return "uaf"
    if "fmt" in n or "format" in n:
        return "format_string"
    if "double_free" in n:
        return "double_free"
    # 扩展模式: 目录名中的其他暗示
    if "event_uaf" in n or "ev_uaf" in n:
        return "uaf"
    if "restricted_copy" in n or "buffer_copy" in n:
        return "stack_overflow"
    if "copy" in n and "restricted" in n:
        return "stack_overflow"
    # double_free 变体: _df 后缀, 特定模式
    if n.endswith("_df") or "_df_" in n:
        return "double_free"
    if any(k in n for k in ("aliased", "conditional", "loop_df", "struct_field",
                              "array_df", "realloc_df", "interproc", "null_check",
                              "signal_df", "error_path", "list_df", "thread_df",
                              "wrapper_df", "shrink_df")):
        return "double_free"
    return None


def extract_imports_and_code(sample_dir: Path):
    """从样本目录中的二进制和源码提取信息。"""
    result = {"code": "", "imports": {}, "strings": [], "arch": "x86_64"}
    src_file = sample_dir / "vuln.c"
    if src_file.exists():
        result["code"] = src_file.read_text(encoding="utf-8", errors="replace")

    # 查找二进制
    elf = None
    for name in ("vuln.exe", "vuln", "vuln.elf"):
        p = sample_dir / name
        if p.is_file():
            elf = p; break
    if not elf:
        elfs = list(sample_dir.glob("vuln*"))
        elfs = [e for e in elfs if e.suffix in (".exe", ".elf", "") and not e.name.endswith(".c")]
        if elfs: elf = elfs[0]

    if elf and elf.exists():
        try:
            import subprocess
            # PE or ELF
            proc = subprocess.run(["objdump", "-f", str(elf)], capture_output=True,
                                  text=True, timeout=5)
            out = proc.stdout.lower()
            is_pe = "pei" in out or "pe32" in out
            result["arch"] = "i386" if ("elf32" in out or "i386" in out) else "x86_64"

            if is_pe:
                proc = subprocess.run(["objdump", "-p", str(elf)], capture_output=True,
                                      text=True, timeout=10)
                dll = None
                for line in proc.stdout.splitlines():
                    s = line.strip()
                    if "DLL Name:" in s:
                        dll = s.split("DLL Name:")[-1].strip()
                        result["imports"].setdefault("all_imports", {}).setdefault(dll, [])
                    elif dll and re.match(r'^[0-9a-fA-F]{8}\s', s):
                        parts = s.split()
                        if len(parts) >= 4 and not re.match(r'^[0-9a-fA-F]+$', parts[-1]):
                            result["imports"]["all_imports"][dll].append(parts[-1])
                    elif not s:
                        dll = None
            else:
                proc = subprocess.run(["objdump", "-T", str(elf)], capture_output=True,
                                      text=True, timeout=10)
                for line in proc.stdout.splitlines():
                    if "*UND*" in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            result["imports"].setdefault("all_imports", {})\
                                .setdefault("libc.so.6", []).append(parts[-1])
        except Exception:
            pass

    return result


def run_detector(vtype: str, info: dict, sample_name: str) -> dict:
    """运行对应类型的检测器。"""
    if vtype not in DETECTORS:
        return {"error": f"no detector for {vtype}", "findings": 0}

    mod_name, func_name, _ = DETECTORS[vtype]
    try:
        mod = __import__(mod_name, fromlist=[func_name])
        fn = getattr(mod, func_name)

        t0 = time.time()
        code = info["code"]; imports = info["imports"]
        strings = info.get("strings", [])

        if vtype == "heap_overflow":
            result = fn(code=code, imports=imports, strings=strings,
                       checksec={"arch": info["arch"]})
            findings = result.get("findings", [])
            total = len(findings) if isinstance(findings, list) else result.get("stats", {}).get("total", 0)
            method = result.get("method", mod_name) if isinstance(result, dict) else mod_name
        elif vtype == "stack_overflow":
            findings = fn(code=code, func=sample_name, arch=info["arch"])
            total = len(findings) if isinstance(findings, list) else 0
            method = "stack_overflow_v3"
        elif vtype == "int_overflow":
            findings = fn(code=code, func=sample_name)
            total = len(findings) if isinstance(findings, list) else 0
            method = "int_overflow_v2"
        elif vtype == "uaf":
            findings = fn(code=code, func_name=sample_name)
            total = len(findings) if isinstance(findings, list) else 0
            method = "uaf_lifecycle"
        elif vtype == "format_string":
            findings = fn(code=code, func_name=sample_name)
            total = len(findings) if isinstance(findings, list) else 0
            method = "format_string_v3"
        elif vtype == "double_free":
            findings = fn(code=code, func=sample_name)
            total = len(findings) if isinstance(findings, list) else 0
            method = "double_free_analyzer"
        else:
            findings = []; total = 0; method = "unknown"

        elapsed = round((time.time() - t0) * 1000, 1)
        return {"findings": total, "elapsed_ms": elapsed,
                "details": findings[:5] if isinstance(findings, list) else [],
                "method": method}
    except Exception as e:
        return {"error": str(e)[:120], "findings": 0, "elapsed_ms": 0}


def main():
    # 加载 ground truth
    gt_data = {}
    if GT_FILE.exists():
        with open(GT_FILE) as f:
            gt_data = json.load(f).get("samples", {})

    # 收集所有样本
    all_dirs = sorted(d for d in SAMPLES_DIR.iterdir()
                      if d.is_dir() and d.name != "tests")

    # 按漏洞类型分组统计
    stats_by_type = defaultdict(lambda: {"TP":0,"FP":0,"TN":0,"FN":0,"samples":0})
    all_results = []

    print(f"{'='*70}")
    print(f"UNIFIED REGRESSION TEST — {len(all_dirs)} samples across all vuln types")
    print(f"{'='*70}")

    for d in all_dirs:
        vtype = classify_sample(d.name)
        if vtype is None:
            print(f"  SKIP {d.name}: unclassified")
            continue

        gt = gt_data.get(d.name, {})
        is_vuln = gt.get("is_vulnerable", None)

        # 对样本运行对应检测器
        info = extract_imports_and_code(d)
        result = run_detector(vtype, info, d.name)
        findings = result["findings"]
        detected = findings > 0

        # 判定
        if is_vuln is True:
            status = "TP" if detected else "FN"
        elif is_vuln is False:
            status = "FP" if detected else "TN"
        else:
            # 无 ground truth: 根据类型推断期望
            if "NEG-" in d.name:
                status = "FP" if detected else "TN"
            elif "CVE-" in d.name:
                status = "TP" if detected else "FN"
            else:
                status = "UNKNOWN"

        if status != "UNKNOWN":
            stats_by_type[vtype][status] += 1
            stats_by_type[vtype]["samples"] += 1

        elapsed = result.get("elapsed_ms", 0)
        err = result.get("error", "")
        tag = f"[{status}]" if status != "UNKNOWN" else "[??]"
        print(f"  {tag} {vtype:16s} {d.name:40s} f={findings:2d} {elapsed:6.1f}ms"
              + (f" ERR={err}" if err else ""))

        all_results.append({
            "sample": d.name, "vuln_type": vtype,
            "is_vulnerable": is_vuln, "status": status,
            "findings": findings, "elapsed_ms": elapsed,
            "detector": vtype, "error": err,
        })

    # 汇总
    print(f"\n{'='*70}")
    print(f"SUMMARY BY VULNERABILITY TYPE")
    print(f"{'='*70}")
    print(f"{'Type':<20s} {'Samples':>7s} {'TP':>4s} {'FP':>4s} {'TN':>4s} {'FN':>4s}  "
          f"{'Recall':>7s} {'Prec':>7s} {'FPR':>7s} {'F1':>7s}")
    print(f"{'-'*70}")

    grand_tp = grand_fp = grand_tn = grand_fn = 0
    for vtype in sorted(stats_by_type.keys()):
        st = stats_by_type[vtype]
        tp, fp, tn, fn = st["TP"], st["FP"], st["TN"], st["FN"]
        grand_tp += tp; grand_fp += fp; grand_tn += tn; grand_fn += fn
        rec = tp / max(tp + fn, 1)
        prec = tp / max(tp + fp, 1)
        fpr = fp / max(fp + tn, 1)
        f1 = 2 * prec * rec / max(prec + rec, 0.01)
        print(f"{vtype:<20s} {st['samples']:>7d} {tp:>4d} {fp:>4d} {tn:>4d} {fn:>4d}  "
              f"{rec*100:>6.1f}% {prec*100:>6.1f}% {fpr*100:>6.1f}% {f1:>7.3f}")

    # 总计
    total_rec = grand_tp / max(grand_tp + grand_fn, 1)
    total_prec = grand_tp / max(grand_tp + grand_fp, 1)
    total_fpr = grand_fp / max(grand_fp + grand_tn, 1)
    total_f1 = 2 * total_prec * total_rec / max(total_prec + total_rec, 0.01)

    print(f"{'-'*70}")
    print(f"{'TOTAL':<20s} {sum(s['samples'] for s in stats_by_type.values()):>7d} "
          f"{grand_tp:>4d} {grand_fp:>4d} {grand_tn:>4d} {grand_fn:>4d}  "
          f"{total_rec*100:>6.1f}% {total_prec*100:>6.1f}% {total_fpr*100:>6.1f}% {total_f1:>7.3f}")

    # 导出
    with open(RESULTS_FILE, "w") as f:
        json.dump({
            "summary_by_type": {t: dict(st) for t, st in stats_by_type.items()},
            "total": {"TP": grand_tp, "FP": grand_fp, "TN": grand_tn, "FN": grand_fn,
                      "Recall": round(total_rec*100,1), "Precision": round(total_prec*100,1),
                      "FPR": round(total_fpr*100,1), "F1": round(total_f1,3)},
            "details": all_results,
            "timestamp": __import__("datetime").datetime.now().isoformat(),
        }, f, indent=2, ensure_ascii=False, default=str)
    print(f"\nResults: {RESULTS_FILE}")
    return all_results, stats_by_type


if __name__ == "__main__":
    main()
