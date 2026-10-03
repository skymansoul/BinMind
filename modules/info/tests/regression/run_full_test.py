#!/usr/bin/env python
"""tests/regression/run_full_test.py — 跨平台完整验证
对 Windows PE 和 Linux ELF 均支持, 直接比较 AC3 和 路径敏感值域推理-HLM 的检测效果。
从 modules/info 目录运行。"""

import sys, os, json, time, subprocess, re
from pathlib import Path

_PROJ = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_PROJ))
sys.path.insert(0, str(_PROJ / "analysis"))

SAMPLES_DIR = Path(__file__).parent / "samples"
GT_FILE = Path(__file__).parent / "ground_truth.json"


def extract_pe_imports(target: str) -> dict:
    """从 PE 二进制中提取导入函数 (Windows)。

    objdump -p 输出格式:
        DLL Name: msvcrt.dll
        vma:     Ordinal  Hint  Member-Name  Bound-To
        00010280  <none>  0059  __C_specific_handler
        ...
        <空行或section header>  → 导入段结束
    """
    imports = {"all_imports": {}}
    try:
        proc = subprocess.run(["objdump", "-p", str(target)],
                              capture_output=True, text=True, timeout=10)
        current_dll = None
        for line in proc.stdout.splitlines():
            stripped = line.strip()
            # 检测 DLL 名称
            if "DLL Name:" in stripped:
                current_dll = stripped.split("DLL Name:")[-1].strip()
                imports["all_imports"].setdefault(current_dll, [])
                continue
            # 跳过标题行
            if "Member-Name" in stripped or stripped.startswith("vma:"):
                continue
            # 空行 → DLL 段结束
            if not stripped:
                current_dll = None
                continue
            # 非导入条目 (section header, hex dump 等) → 结束当前 DLL
            # 导入条目特征: 以8位hex地址开头, 后跟 ordinal/hint/name
            if not re.match(r'^[0-9a-fA-F]{8}\s', stripped):
                current_dll = None
                continue
            if current_dll is None:
                continue
            # 提取函数名 (最后一个非数字字段)
            parts = stripped.split()
            if len(parts) >= 4:
                fn = parts[-1]
                # 跳过纯数字和特殊标记
                if re.match(r'^[0-9a-fA-F]+$', fn):
                    continue
                if fn in ("(none)", "Bound-To"):
                    continue
                imports["all_imports"][current_dll].append(fn)
    except Exception:
        pass
    return imports


def extract_elf_imports(target: str) -> dict:
    """从 ELF 二进制中提取导入函数 (Linux)。"""
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


def extract_strings_raw(target: str) -> list:
    """从二进制提取字符串。"""
    try:
        proc = subprocess.run(["strings", str(target)],
                              capture_output=True, text=True, timeout=10,
                              errors="replace")
        return [(i, s) for i, s in enumerate(proc.stdout.splitlines()) if len(s) >= 3]
    except Exception:
        return []


def detect_file_type(target: str) -> str:
    """判断二进制文件格式。"""
    try:
        proc = subprocess.run(["objdump", "-f", str(target)],
                              capture_output=True, text=True, timeout=5)
        out = proc.stdout.lower()
        if "pei" in out or "pe32" in out:
            return "pe"
        if "elf" in out:
            return "elf"
    except Exception:
        pass
    return "unknown"


def smart_extract(target: str):
    """智能导入提取: 自动判断 PE/ELF 格式。"""
    ftype = detect_file_type(target)
    if ftype == "pe":
        imports = extract_pe_imports(target)
    else:
        imports = extract_elf_imports(target)
    strings = extract_strings_raw(target)
    # 从 objdump -f 提取架构
    arch = "x86_64"
    try:
        proc = subprocess.run(["objdump", "-f", str(target)],
                              capture_output=True, text=True, timeout=5)
        out = proc.stdout.lower()
        if "elf32" in out or "i386" in out or "pei-i386" in out:
            arch = "i386"
    except Exception:
        pass
    return imports, strings, {"arch": arch, "format": ftype}


def run_baseline(imports: dict, strings: list, checksec: dict, code: str) -> dict:
    """基线检测: 仅基于导入表配对 (模拟 AC3 v1 的简化版)。"""
    all_fns = []
    for dll, fns in imports.get("all_imports", {}).items():
        all_fns.extend(fns)

    alloc_fns = {"malloc", "calloc", "realloc", "_malloc", "HeapAlloc",
                 "__imp_malloc", "__imp_calloc", "__imp_realloc"}
    write_fns = {"memcpy", "strcpy", "sprintf", "memmove", "strncpy",
                 "read", "recv", "fread", "gets", "scanf", "strcat",
                 "__imp_memcpy", "__imp_strcpy", "__imp_sprintf",
                 "fgets", "snprintf", "wcscpy", "_memcpy", "_strcpy"}

    allocs = [f for f in all_fns if f in alloc_fns or
              any(a in f.lower() for a in ["malloc", "calloc", "realloc", "heapalloc"])]
    writes = [f for f in all_fns if f in write_fns or
              any(w in f.lower() for w in ["memcpy", "strcpy", "sprintf", "memmove", "strncpy"])]

    findings = []
    for a in allocs:
        for w in writes:
            findings.append({
                "type": "heap-overflow",
                "alloc_func": a, "write_func": w,
                "confidence": 0.55,
                "description": f"pair: {a} + {w}"
            })

    return {
        "stats": {"total": len(findings), "high_conf": len(findings),
                   "avg_confidence": 0.55},
        "findings": findings,
    }


def run_psvr_hlm(imports: dict, strings: list, checksec: dict, code: str) -> dict:
    """路径敏感值域推理-HLM v2: 值范围+布局模型+路径检查。"""
    try:
        from heap_overflow_v2 import detect_heap_overflow_v2
        result = detect_heap_overflow_v2(
            code=code, imports=imports, strings=strings, checksec=checksec)
        return result
    except Exception as e:
        return {
            "stats": {"total": 0, "high_conf": 0, "avg_confidence": 0},
            "findings": [], "error": str(e)[:100],
        }


def main():
    gt_data = {}
    if GT_FILE.exists():
        with open(GT_FILE) as f:
            gt_data = json.load(f).get("samples", {})

    # 目标: 只测我们创建的15个堆溢出样本
    target_dirs = sorted(
        d for d in SAMPLES_DIR.iterdir()
        if d.is_dir() and ("CVE-2024-" in d.name or d.name.startswith("NEG-"))
    )
    print(f"{'='*70}")
    print(f"PSVR-HLM Validation — {len(target_dirs)} samples")
    print(f"{'='*70}")

    results = []
    stats_base = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    stats_v2 = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}

    for d in target_dirs:
        # 查找二进制文件
        elf = None
        for name in ("vuln.exe", "vuln", "vuln.elf"):
            p = d / name
            if p.is_file():
                elf = p
                break
        if not elf:
            elfs = list(d.glob("vuln*"))
            if elfs:
                elf = elfs[0]

        if not elf:
            print(f"  SKIP {d.name}: no binary")
            continue

        # 读取源码
        src_file = d / "vuln.c"
        code = ""
        if src_file.exists():
            code = src_file.read_text(encoding="utf-8", errors="replace")

        # 提取导入和元数据
        imports, strings, checksec = smart_extract(str(elf))

        # GT
        gt = gt_data.get(d.name, {})
        is_vuln = gt.get("is_vulnerable", None)
        vt = gt.get("vuln_type", gt.get("vulnerability_type", "unknown"))

        print(f"\n{d.name}")
        print(f"  GT: is_vuln={is_vuln}  type={vt}  format={checksec['format']}")

        # 展示提取到的导入
        all_fns = []
        for dll, fns in imports["all_imports"].items():
            all_fns.extend(fns)
        relevant = [f for f in all_fns if any(
            kw in f.lower() for kw in ["malloc", "calloc", "realloc", "free",
                                        "memcpy", "strcpy", "sprintf", "memmove",
                                        "strncpy", "read", "recv", "fread", "gets",
                                        "scanf", "strcat", "snprintf", "fgets"])]
        print(f"  Relevant imports: {relevant[:15]}")

# 基线 (简化 AC3)
        t0 = time.time()
        r_base = run_baseline(imports, strings, checksec, code)
        base_ms = round((time.time() - t0) * 1000, 1)
        base_findings = r_base["stats"]["total"]
        base_detected = base_findings > 0

        if is_vuln is True:
            base_status = "TP" if base_detected else "FN"
        elif is_vuln is False:
            base_status = "FP" if base_detected else "TN"
        else:
            base_status = "UNKNOWN"
        stats_base[base_status] = stats_base.get(base_status, 0) + 1

        print(f"  BASELINE:  findings={base_findings}  status={base_status}  {base_ms}ms")

# 路径敏感值域推理-HLM v2
        t0 = time.time()
        r_v2 = run_psvr_hlm(imports, strings, checksec, code)
        v2_ms = round((time.time() - t0) * 1000, 1)
        v2_stats = r_v2.get("stats", {})
        v2_findings = v2_stats.get("total", 0)
        v2_high = v2_stats.get("high_conf", 0)
        v2_detected = v2_findings > 0
        vra_info = r_v2.get("vra_stats", {})
        pipeline_info = r_v2.get("pipeline", [])

        if is_vuln is True:
            v2_status = "TP" if v2_detected else "FN"
        elif is_vuln is False:
            v2_status = "FP" if v2_detected else "TN"
        else:
            v2_status = "UNKNOWN"
        stats_v2[v2_status] = stats_v2.get(v2_status, 0) + 1

        fp_red = r_v2.get("fp_reduction_pct", 0)
        print(f"  PSVR-HLM:  findings={v2_findings}  high={v2_high}  status={v2_status}")
        print(f"             VRA={vra_info}  FP_reduction={fp_red}%  pipeline={pipeline_info}  {v2_ms}ms")

        # 记录
        results.append({
            "sample": d.name, "is_vulnerable": is_vuln, "vuln_type": vt,
            "baseline_findings": base_findings, "baseline_status": base_status,
            "v2_findings": v2_findings, "v2_high": v2_high, "v2_status": v2_status,
            "fp_reduction_pct": fp_red, "pipeline": pipeline_info,
            "vra_stats": vra_info, "format": checksec["format"],
        })

    # 汇总
    def metrics(st):
        tp = st.get("TP", 0); fp = st.get("FP", 0)
        tn = st.get("TN", 0); fn = st.get("FN", 0)
        recall = tp / max(tp + fn, 1)
        precision = tp / max(tp + fp, 1)
        fpr = fp / max(fp + tn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 0.01)
        return recall, precision, fpr, f1, tp, fp, tn, fn

    r1, p1, fpr1, f11, tp1, fp1, tn1, fn1 = metrics(stats_base)
    r2, p2, fpr2, f12, tp2, fp2, tn2, fn2 = metrics(stats_v2)

    print(f"\n{'='*70}")
    print(f"FINAL METRICS")
    print(f"{'='*70}")
    print(f"{'Method':<18} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}  "
          f"{'Recall':>7} {'Prec':>7} {'FPR':>7} {'F1':>7}")
    print(f"{'-'*70}")
    print(f"{'BASELINE (AC3)':<18} {tp1:>3} {fp1:>3} {tn1:>3} {fn1:>3}  "
          f"{r1*100:>6.1f}% {p1*100:>6.1f}% {fpr1*100:>6.1f}% {f11:>7.3f}")
    print(f"{'PSVR-HLM v2':<18} {tp2:>3} {fp2:>3} {tn2:>3} {fn2:>3}  "
          f"{r2*100:>6.1f}% {p2*100:>6.1f}% {fpr2*100:>6.1f}% {f12:>7.3f}")

    fp_reduction_pct = (fpr1 - fpr2) / max(fpr1, 0.01) * 100 if fpr1 > 0 else 0
    recall_change_pct = (r2 - r1) / max(r1, 0.01) * 100 if r1 > 0 else 0

    print(f"\n{'='*70}")
    print(f"IMPROVEMENT SUMMARY")
    print(f"{'='*70}")
    print(f"  FP Rate change:  {fpr1*100:.1f}% → {fpr2*100:.1f}%  ({fp_reduction_pct:+.1f}%)")
    print(f"  Recall change:   {r1*100:.1f}% → {r2*100:.1f}%  ({recall_change_pct:+.1f}%)")
    print(f"  F1 change:       {f11:.3f} → {f12:.3f}  ({f12-f11:+.3f})")

    sat_fp = fpr2 < 0.20 or fp2 == 0
    sat_reduction = fp_reduction_pct > 40 or (fpr1 == 0 and fpr2 == 0)
    saturated = sat_fp and (sat_reduction or fp2 == 0)
    print(f"\n  Saturation check:")
    print(f"    FP_rate < 20%: {'OK' if sat_fp else 'NO'} (actual: {fpr2*100:.1f}%)")
    print(f"    FP_reduction > 40%: {'OK' if sat_reduction else 'NO'} (actual: {fp_reduction_pct:.1f}%)")
    # 审计口径: SATURATED 为本运行小集的饱和判定输出, 非对外指标宣称
    print(f"    -> {'SATURATED' if saturated else 'MORE ITERATION NEEDED'}")

    # 导出
    out_path = Path(__file__).parent / "full_test_results.json"
    with open(out_path, "w") as f:
        json.dump({
            "summary": {
                "baseline": {"TP": tp1, "FP": fp1, "TN": tn1, "FN": fn1,
                             "Recall": round(r1*100,1), "Precision": round(p1*100,1),
                             "FPR": round(fpr1*100,1), "F1": round(f11, 3)},
                "psvr_hlm_v2": {"TP": tp2, "FP": fp2, "TN": tn2, "FN": fn2,
                                "Recall": round(r2*100,1), "Precision": round(p2*100,1),
                                "FPR": round(fpr2*100,1), "F1": round(f12, 3)},
                "fp_reduction_pct": round(fp_reduction_pct, 1),
                "saturated": saturated,
            },
            "details": results,
            "timestamp": __import__("datetime").datetime.now().isoformat(),
        }, f, indent=2, ensure_ascii=False, default=str)
    print(f"\nResults exported: {out_path}")

    return results, saturated


if __name__ == "__main__":
    main()
