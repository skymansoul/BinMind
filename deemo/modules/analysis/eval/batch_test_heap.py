# 堆溢出检测批量基准测试 — CVE样本(召回) + FP倾向安全样本(精确率)
# 输出 JSON + CSV 结果供 plot_comparison.py 使用.
# 创建: 2026-05-13

import sys, json, time, csv
from pathlib import Path
from typing import Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
# eval/ → analysis/ → modules/ → deemo/  (parents[2])
PROJECT_ROOT = SCRIPT_DIR.parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

BENCHMARK_ROOT = PROJECT_ROOT / "modules/analysis/benchmark"
CVE_SAMPLES_DIR = BENCHMARK_ROOT / "samples"
FP_SAFE_DIR = BENCHMARK_ROOT / "samples_heap_safe"
RESULTS_DIR = SCRIPT_DIR / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def analyze_one_with_func_split(binary_path: str) -> dict:
    """全局分析 + 按函数分类findings.

    运行一次全局检测器(保留跨函数上下文), 然后根据finding的
    地址判断属于_vuln还是_safe函数.
    """
    t0 = time.perf_counter()
    result = {"binary": binary_path, "vuln_findings": [], "safe_findings": [],
              "other_findings": [], "vuln_funcs": 0, "safe_funcs": 0,
              "time_ms": 0, "error": "", "instructions": 0}

    try:
        ins, fmt, main_addr, ranges = disassemble_binary(binary_path)
        result["instructions"] = len(ins)
        result["format"] = fmt

        # 构建函数名映射: address → func_name
        func_names = {}  # 每个地址属于哪个函数
        for lo, hi in ranges:
            for i in ins:
                a = i.get("address", 0)
                if lo <= a < hi:
                    func_names[a] = f"func_{lo:x}"
                    break
            # 尝试从call指令解析符号名
            for i in ins:
                a = i.get("address", 0)
                if not (lo <= a < hi):
                    continue
                ops = i.get("operands", [])
                for op in ops:
                    if "_vuln" in op or "_safe" in op:
                        # 函数入口通常有符号引用
                        pass
        # 简化: 扫描所有指令寻找符号引用
        func_name_by_addr = {}
        for i in ins:
            a = i.get("address", 0)
            ops = i.get("operands", [])
            for op in ops:
                if "<" in op and ">" in op:
                    fname = op.split("<")[-1].split(">")[0].split("+")[0]
                    if fname and not fname.startswith("0x"):
                        func_name_by_addr[a] = fname

        # 全局分析
        det = HeapOverflowDetector(AllocatorFamily.GLIBC,
                                   use_win64_abi="pei" in fmt.lower())
        if main_addr:
            det.set_min_user_addr(main_addr)
        if ranges:
            det.set_user_func_ranges(ranges)
        det.pre_analyze(ins)
        for i in ins:
            det.analyze_instruction(i)
        findings = det.finalize(ins)

        # 按函数分类findings
        for f in findings:
            write_addr = f.get("write_addr", 0)
            # 确定finding属于哪个函数
            in_vuln = in_safe = False
            for lo, hi in ranges:
                if lo <= write_addr < hi:
                    # 检查此范围是否有vuln/safe引用
                    for addr, name in func_name_by_addr.items():
                        if lo <= addr < hi:
                            if "_vuln" in name.lower():
                                in_vuln = True
                            if "_safe" in name.lower():
                                in_safe = True
                            break
                    break

            entry = {
                "severity": f.get("severity", "unknown"),
                "write_addr": f.get("write_addr", 0),
                "dangerous_func": f.get("dangerous_func", ""),
                "alloc_size": f.get("alloc_size", 0),
                "write_size": f.get("write_size", 0),
            }
            if in_vuln:
                result["vuln_findings"].append(entry)
            elif in_safe:
                result["safe_findings"].append(entry)
            else:
                result["other_findings"].append(entry)

        # 统计vuln/safe函数数量
        seen_vuln = set()
        seen_safe = set()
        for addr, name in func_name_by_addr.items():
            for lo, hi in ranges:
                if lo <= addr < hi:
                    if "_vuln" in name.lower() and lo not in seen_vuln:
                        seen_vuln.add(lo)
                        result["vuln_funcs"] += 1
                    if "_safe" in name.lower() and lo not in seen_safe:
                        seen_safe.add(lo)
                        result["safe_funcs"] += 1
                    break

    except Exception as e:
        result["error"] = str(e)[:200]

    result["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return result


def analyze_one_simple(binary_path: str) -> dict:
    """简单全局分析 — 用于CVE样本(不需要按函数分类)."""
    t0 = time.perf_counter()
    result = {"binary": binary_path, "findings": [], "time_ms": 0,
              "error": "", "instructions": 0}

    try:
        ins, fmt, main_addr, ranges = disassemble_binary(binary_path)
        result["instructions"] = len(ins)
        result["format"] = fmt

        det = HeapOverflowDetector(AllocatorFamily.GLIBC,
                                   use_win64_abi="pei" in fmt.lower())
        if main_addr:
            det.set_min_user_addr(main_addr)
        if ranges:
            det.set_user_func_ranges(ranges)
        det.pre_analyze(ins)
        for i in ins:
            det.analyze_instruction(i)
        findings = det.finalize(ins)

        result["findings"] = [{
            "severity": f.get("severity", "unknown"),
            "write_addr": f.get("write_addr", 0),
            "dangerous_func": f.get("dangerous_func", ""),
            "alloc_size": f.get("alloc_size", 0),
            "write_size": f.get("write_size", 0),
            "filter_stage": f.get("filter_stage", ""),
        } for f in findings]

    except Exception as e:
        result["error"] = str(e)[:200]

    result["time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return result


def run_cve_benchmark_direct() -> List[dict]:
    """直接扫描CVE目录中的所有.exe文件 → 测召回率."""
    results = []
    exe_files = sorted(CVE_SAMPLES_DIR.rglob("*.exe"))
    heap_exes = [e for e in exe_files
                 if "heap" in e.stem.lower() and "doublefree" not in str(e).lower()]
    print(f"CVE benchmark: {len(heap_exes)} heap overflow binaries found")

    for exe_path in heap_exes:
        name = exe_path.stem
        cve_dir = exe_path.parent.name
        opt = "O2" if "_O2" in name else ("Os" if "_Os" in name else "O0")

        print(f"  {name}...", end=" ", flush=True)
        r = analyze_one_simple(str(exe_path))
        r["name"] = name
        r["cve"] = cve_dir
        r["type"] = "heap_overflow"
        r["opt"] = opt
        r["is_vuln"] = True
        r["detected"] = len(r["findings"]) > 0
        results.append(r)

        status = "TP" if r["detected"] else "FN!"
        print(f"{status} {len(r['findings'])}f, {r['time_ms']}ms"
              + (f" ERR:{r['error']}" if r['error'] else ""))

    return results


def run_fp_safe_benchmark() -> List[dict]:
    """FP倾向安全样本 → 独立二进制粒度测精确率/误报率.

    v2: 每个pattern编译出 _vuln.exe (应检出=TP) 和 _safe.exe
    (不应检出, 检出即FP). 独立二进制避免了函数归属判定的歧义.
    """
    v2_manifest = FP_SAFE_DIR / "benchmark_fp_safe_v2_manifest.json"
    if not v2_manifest.exists():
        print(f"[WARN] v2 manifest not found: {v2_manifest}")
        return []
    manifest = json.loads(v2_manifest.read_text(encoding="utf-8"))
    compiled = [e for e in manifest if e.get("compiled")]
    print(f"FP-safe benchmark (v2): {len(compiled)} compiled entries")

    results = []
    for entry in compiled:
        binary = entry.get("binary", "")
        if not binary or not Path(binary).exists():
            continue

        name = entry.get("name", Path(binary).stem)
        opt = entry.get("opt", "?")
        is_vuln = entry.get("is_vuln", False)
        print(f"  {name} (O{opt})...", end=" ", flush=True)
        r = analyze_one_simple(binary)
        r["name"] = name
        r["pattern"] = entry.get("pattern", "")
        r["type"] = entry.get("type", "")
        r["opt"] = opt
        r["is_vuln"] = is_vuln

        detected = len(r["findings"]) > 0
        if is_vuln:
            # vuln二进制: 检出=TP, 漏检=FN (不计入FP)
            r["is_tp"] = detected
            r["is_fp"] = False
            r["is_vuln_missed"] = not detected
        else:
            # safe二进制: 检出=FP, 未检出=TN
            r["is_fp"] = detected
            r["is_vuln_missed"] = False

        results.append(r)
        parts = []
        if r.get("is_fp"): parts.append(f"FP({len(r['findings'])} findings!)")
        if r.get("is_vuln_missed"): parts.append("FN(vuln missed!)")
        if not parts and not is_vuln: parts.append("TN")
        if not parts and is_vuln: parts.append("TP")
        parts.append(f"{r['time_ms']}ms")
        print(" ".join(parts))

    return results


def compute_metrics(cve_results: List[dict], fp_results: List[dict]) -> dict:
    """计算 TP/FP/TN/FN/Recall/Precision/FPR/F1.

    CVE样本: 检出=finding → TP, 未检出=FN
    FP-safe v2样本: _vuln检出=TP不计FP; _safe检出=FP; _safe未检出=TN
    """
    tp = sum(1 for r in cve_results if r.get("detected"))
    fn = sum(1 for r in cve_results if not r.get("detected"))

    # v2独立二进制: vuln检出=TP(补充), safe检出=FP, safe未检出=TN
    tp += sum(1 for r in fp_results
              if r.get("is_vuln") and r.get("is_tp"))
    fp = sum(1 for r in fp_results if r.get("is_fp"))
    tn = sum(1 for r in fp_results
             if (not r.get("is_vuln")) and not r.get("is_fp"))
    fn += sum(1 for r in fp_results
              if r.get("is_vuln") and r.get("is_vuln_missed"))

# vuln函数检出数 (额外信息)
    vuln_missed = sum(1 for r in fp_results if r.get("is_vuln_missed"))

    recall = tp / max(tp + fn, 1)
    precision = tp / max(tp + fp, 1)
    fpr = fp / max(fp + tn, 1)
    f1 = 2 * recall * precision / max(recall + precision, 1e-9)

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "vuln_missed_in_safe_samples": vuln_missed,
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "fpr": round(fpr, 4),
        "f1": round(f1, 4),
        "cve_samples": len(cve_results),
        "fp_safe_samples": len(fp_results),
    }


def main():
    print("=" * 60)
    print("Heap Overflow Detection — Comprehensive Benchmark")
    print("=" * 60)

    print("\n--- CVE Samples (Recall Test) ---")
    cve_results = run_cve_benchmark_direct()

    print(f"\n--- FP-Prone Safe Samples (Precision Test) ---")
    fp_results = run_fp_safe_benchmark()

    metrics = compute_metrics(cve_results, fp_results)

    # 合并输出
    all_results = {
        "tool": "BinMind",
        "version": "v3 (5-stage FP filter)",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "metrics": metrics,
        "cve_results": cve_results,
        "fp_safe_results": fp_results,
    }

    # JSON 输出
    json_path = RESULTS_DIR / "heap_benchmark_binmind.json"
    json_path.write_text(json.dumps(all_results, indent=2, default=str,
                                     ensure_ascii=False))
    print(f"\nJSON output: {json_path}")

    # CSV 输出
    csv_path = RESULTS_DIR / "heap_benchmark_binmind.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "name", "type", "opt", "detected", "findings_count",
            "time_ms", "instructions", "error"])
        w.writeheader()
        for r in cve_results + fp_results:
            w.writerow({
                "name": r.get("name", ""),
                "type": r.get("type", ""),
                "opt": r.get("opt", ""),
                "detected": r.get("detected", False),
                "findings_count": len(r.get("findings", [])),
                "time_ms": r.get("time_ms", 0),
                "instructions": r.get("instructions", 0),
                "error": r.get("error", "")[:100],
            })

    # 汇总
    print(f"\n{'='*60}")
    print(f"BinMind Heap Overflow v3 Benchmark Summary")
    print(f"{'='*60}")
    m = metrics
    print(f"  CVE samples:      {m['cve_samples']}")
    print(f"  FP-safe samples:  {m['fp_safe_samples']}")
    print(f"  TP={m['tp']}  FP={m['fp']}  TN={m['tn']}  FN={m['fn']}")
    print(f"  Recall:    {m['recall']:.4f} ({m['recall']*100:.1f}%)")
    print(f"  Precision: {m['precision']:.4f} ({m['precision']*100:.1f}%)")
    print(f"  FPR:       {m['fpr']:.4f} ({m['fpr']*100:.1f}%)")
    print(f"  F1 Score:  {m['f1']:.4f}")

    return all_results


if __name__ == "__main__":
    main()
