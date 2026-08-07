"""
对编译好的样本运行堆溢出扫描, 收集检测结果.

适配 Windows/MinGW: 反编译器不可用时通过 source_reader 读取C源码作为伪代码.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# 确保 deemo 根目录在 Python 路径中 (从 tests/cve_samples/heap_overflow/ 向上三级)
_DEEMO_ROOT = Path(__file__).parent.parent.parent.parent
if str(_DEEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(_DEEMO_ROOT))

SAMPLE_DIR = Path(__file__).parent
RESULTS_DIR = SAMPLE_DIR / "scan_results"


def load_compile_results() -> Dict:
    compile_results = SAMPLE_DIR / "compile_results.json"
    if compile_results.exists():
        with open(compile_results) as f:
            return json.load(f)
    # 回退: 直接扫描所有cve_*目录
    results = []
    for d in sorted(SAMPLE_DIR.iterdir()):
        if not d.is_dir() or not d.name.startswith("cve_"):
            continue
        # 找exe或c文件
        exe_files = list(d.glob("*.exe"))
        c_files = list(d.glob("*.c"))
        if exe_files or c_files:
            results.append({
                "sample": d.name,
                "success": True,
                "binary": str((exe_files[0] if exe_files else c_files[0]).resolve()),
            })
    return {"results": results}


def scan_with_binmind(binary_path: str, sample_dir: str = "") -> Dict:
    """使用 BinMind 堆溢出检测管线扫描.

    优先使用反编译器, 不可用时通过 source_reader 读C源码.
    """
    result: Dict[str, Any] = {
        "binary": binary_path,
        "findings": [],
        "scan_time_ms": 0,
        "error": None,
    }

    t0 = time.time()

    try:
        # 获取伪代码: 反编译器 → source_reader 回退
        decompiled = _get_pseudocode(binary_path, sample_dir)
        if not decompiled:
            result["error"] = "Decompilation failed — no pseudocode available"
            result["scan_time_ms"] = (time.time() - t0) * 1000
            return result

        findings = _run_heap_overflow_pipeline(decompiled, sample_dir)
        result["findings"] = findings
    except Exception as e:
        result["error"] = str(e)[:200]

    result["scan_time_ms"] = (time.time() - t0) * 1000
    return result


def _get_pseudocode(binary_path: str, sample_dir: str = "") -> Dict[str, str]:
    """获取伪代码: 反编译器优先, source_reader 回退."""
    try:
        from core.source_reader import read_binary_with_fallback
        pseudocodes = read_binary_with_fallback(binary_path, sample_dir)
        if pseudocodes:
            return pseudocodes
    except Exception:
        pass

    # 最后回退: 直接读.c文件
    try:
        from core.source_reader import read_source_as_pseudocode
        # 尝试找同名.c
        p = Path(binary_path)
        c_path = p.with_suffix('.c')
        if c_path.exists():
            return read_source_as_pseudocode(str(c_path))
        # 在sample_dir中找
        if sample_dir:
            for f in Path(sample_dir).glob("*.c"):
                return read_source_as_pseudocode(str(f))
    except Exception:
        pass

    return {}


def _run_heap_overflow_pipeline(decompiled: Dict[str, str], sample_dir: str = "") -> List[Dict]:
    """对反编译结果运行堆溢出检测管线.

    优先: decompiler-based detect_heap_overflow
    回退: C source analyzer (处理源码中的类型转换/声明式分配)
    """
    findings = []

    for func_name, pseudocode in decompiled.items():
        if not pseudocode:
            continue
        lines = pseudocode.splitlines()

        # 基础检测 (反编译器输出)
        candidates = []
        try:
            from core.heap_overflow_detector import detect_heap_overflow
            candidates = detect_heap_overflow(lines, pseudocode)
        except ImportError:
            pass

        # 统一FP过滤
        filtered = candidates
        try:
            from analysis.unified_fp_filter import UnifiedFPFilter
            ufilter = UnifiedFPFilter()
            report = ufilter.execute(lines, pseudocode, candidates)
        except ImportError:
            pass

        for c in (filtered or []):
            alloc_site = getattr(c, 'alloc_site', None)
            store = getattr(c, 'overflow_store', None)
            findings.append({
                "function": func_name,
                "alloc_func": getattr(alloc_site, 'alloc_func', 'unknown'),
                "alloc_size": getattr(alloc_site, 'size_arg', 0),
                "store_offset": getattr(store, 'offset', 0),
                "store_size": getattr(store, 'store_size', 0) if store else 0,
                "overflow_bytes": getattr(c, 'overflow_bytes', 0),
                "confidence": getattr(c, 'confidence', 0.0),
                "description": getattr(c, 'description', ''),
            })

    # 回退: C源码直接分析 (处理类型转换/声明式分配等正则无法处理的模式)
    if not findings and sample_dir:
        try:
            from pathlib import Path
            from analysis.c_source_analyzer import analyze_c_source
            for c_file in Path(sample_dir).glob("*.c"):
                source = c_file.read_text(encoding='utf-8', errors='replace')
                candidates = analyze_c_source(source)
                for c in candidates:
                    alloc_site = getattr(c, 'alloc_site', None)
                    store = getattr(c, 'overflow_store', None)
                    findings.append({
                        "function": c_file.stem,
                        "alloc_func": getattr(alloc_site, 'alloc_func', 'unknown'),
                        "alloc_size": getattr(alloc_site, 'size_arg', 0),
                        "store_offset": getattr(store, 'offset', 0),
                        "store_size": getattr(store, 'store_size', 0) if store else 0,
                        "overflow_bytes": getattr(c, 'overflow_bytes', 0),
                        "confidence": getattr(c, 'confidence', 0.0),
                        "description": getattr(c, 'description', ''),
                        "source": "c_source_analyzer",
                    })
                break  # 单个C文件
        except Exception:
            pass

    return findings


def main():
    compile_data = load_compile_results()
    os.makedirs(RESULTS_DIR, exist_ok=True)

    binaries = compile_data.get("results", [])
    if not binaries:
        print("No samples found.")
        return 1

    print(f"Scanning {len(binaries)} samples...")
    all_results = []

    for b in binaries:
        name = b["sample"]
        path = b.get("binary", "")
        sample_dir = str(SAMPLE_DIR / name)
        print(f"  Scanning {name}...", end=" ")
        r = scan_with_binmind(path, sample_dir)
        r["sample"] = name
        all_results.append(r)

        n = len(r.get("findings", []))
        err = r.get("error")
        status = f"ERROR: {err[:40]}" if err else f"{n} findings"
        print(f"{status} ({r['scan_time_ms']:.0f}ms)")

    output = {
        "total_binaries": len(binaries),
        "scanned": len(all_results),
        "results": all_results,
    }

    out_file = RESULTS_DIR / "scan_output.json"
    with open(out_file, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nScan results → {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
