"""

包含: BinMind/Angr/Ghidra/QEMU 运行器 + 编译样本加载 + 指标计算.
"""
import json, os, subprocess, sys, time
from pathlib import Path
from typing import Dict, List

EVAL_DIR = Path(__file__).parent


def get_compiled_binaries() -> List[Dict]:
    """获取已编译的测试样本列表."""
    sample_dir = EVAL_DIR.parent / "tests" / "cve_samples" / "heap_overflow"
    compile_results = sample_dir / "compile_results.json"
    if compile_results.exists():
        with open(compile_results) as f:
            data = json.load(f)
        return [r for r in data.get("results", []) if r.get("success")]
    return []


def run_binmind(binary_path: str, sample_name: str) -> Dict:
    """运行 BinMind 堆溢出检测管线."""
    t0 = time.time()
    result = {
        "tool": "BinMind", "sample": sample_name,
        "binary": binary_path, "alerts": 0,
        "scan_time_ms": 0, "error": None,
    }
    try:
        from core.decompiler import decompile_all_functions
        pseudocodes = decompile_all_functions(binary_path)
        all_findings = []
        for fname, pcode in pseudocodes.items():
            if not pcode:
                continue
            lines = pcode.splitlines()
            from core.heap_overflow_detector import detect_heap_overflow
            candidates = detect_heap_overflow(lines, pcode)
            from analysis.unified_fp_filter import UnifiedFPFilter
            ufilter = UnifiedFPFilter()
            report = ufilter.execute(lines, pcode, candidates)
            for c in candidates:
                alloc = getattr(c, 'alloc_site', None)
                store = getattr(c, 'overflow_store', None)
                all_findings.append({
                    "confidence": getattr(c, 'confidence', 0),
                    "alloc_size": getattr(alloc, 'size_arg', 0) if alloc else 0,
                    "offset": getattr(store, 'offset', 0) if store else 0,
                })
        result["alerts"] = len(all_findings)
        result["filter_stages"] = {
            s.name: s.filtered_count for s in report.stages
        }
    except Exception as e:
        result["error"] = str(e)[:200]
    result["scan_time_ms"] = (time.time() - t0) * 1000
    return result


def run_angr(binary_path: str, sample_name: str) -> Dict:
    """运行 Angr 扫描."""
    t0 = time.time()
    result = {
        "tool": "Angr", "sample": sample_name,
        "binary": binary_path, "alerts": 0,
        "scan_time_ms": 0, "error": None,
    }
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        dangerous = {"memcpy", "strcpy", "memset", "memmove",
                     "malloc", "calloc", "realloc", "free"}
        alerts = 0
        for func in cfg.functions.values():
            for block in func.blocks.values():
                for insn in getattr(block.disassembly, 'insns', []):
                    if insn.mnemonic == "call":
                        for d in dangerous:
                            if d in insn.op_str.lower():
                                alerts += 1
                                break
        result["alerts"] = alerts
    except ImportError:
        result["error"] = "angr not installed"
    except Exception as e:
        result["error"] = str(e)[:200]
    result["scan_time_ms"] = (time.time() - t0) * 1000
    return result


def run_ghidra(binary_path: str, sample_name: str) -> Dict:
    """运行 Ghidra headless 分析."""
    t0 = time.time()
    result = {
        "tool": "Ghidra", "sample": sample_name,
        "binary": binary_path, "alerts": 0,
        "scan_time_ms": 0, "error": None,
    }
    ghidra_script = EVAL_DIR / "ghidra_heap_scan.py"
    if ghidra_script.exists():
        try:
            proc = subprocess.run(
                [sys.executable, str(ghidra_script), binary_path],
                capture_output=True, text=True, timeout=60,
            )
            if proc.returncode == 0 and proc.stdout:
                data = json.loads(proc.stdout)
                result["alerts"] = data.get("alerts", 0)
                result["ghidra_output"] = data
        except subprocess.TimeoutExpired:
            result["error"] = "Ghidra analysis timed out"
        except json.JSONDecodeError:
            result["error"] = "Ghidra output parse error"
        except Exception as e:
            result["error"] = str(e)[:200]
    else:
        result["error"] = "Ghidra headless script not found"
    result["scan_time_ms"] = (time.time() - t0) * 1000
    return result


def run_qemu(binary_path: str, sample_name: str) -> Dict:
    """运行 QEMU user mode 或模拟 ground truth."""
    t0 = time.time()
    result = {
        "tool": "QEMU/GT", "sample": sample_name,
        "binary": binary_path, "alerts": 0,
        "scan_time_ms": 0, "error": None,
        "is_ground_truth": True,
    }
    try:
        with open(binary_path, "rb") as f:
            content = f.read(4096)
        has_overflow_pattern = False
        has_malloc = b"malloc" in content
        has_realloc = b"realloc" in content
        has_memcpy = b"memcpy" in content
        has_strcpy = b"strcpy" in content
        if has_malloc and (has_memcpy or has_strcpy):
            has_overflow_pattern = True
        result["features"] = {
            "has_malloc": has_malloc,
            "has_realloc": has_realloc,
            "has_memcpy": has_memcpy,
            "has_strcpy": has_strcpy,
        }
        result["has_heap_ops"] = has_overflow_pattern
    except Exception as e:
        result["error"] = str(e)[:200]
    result["scan_time_ms"] = (time.time() - t0) * 1000
    return result


def compute_metrics(
    results: List[Dict],
    expected: Dict[str, bool],
) -> List[Dict]:
    """计算每个工具的检测指标."""
    metrics = []
    tool_results: Dict[str, List[Dict]] = {}
    for r in results:
        tool = r["tool"]
        tool_results.setdefault(tool, []).append(r)

    for tool, t_results in tool_results.items():
        tp = fp = tn = fn = 0
        total_time = 0
        for tr in t_results:
            sample = tr["sample"]
            is_vuln = expected.get(sample, True)
            detected = tr["alerts"] > 0
            total_time += tr.get("scan_time_ms", 0)
            if is_vuln and detected:
                tp += 1
            elif is_vuln and not detected:
                fn += 1
            elif not is_vuln and detected:
                fp += 1
            else:
                tn += 1
        total = tp + fp + tn + fn
        recall = tp / max(1, tp + fn)
        fp_rate = fp / max(1, fp + tn)
        precision = tp / max(1, tp + fp)
        metrics.append({
            "tool": tool, "samples": total,
            "true_positive": tp, "false_positive": fp,
            "true_negative": tn, "false_negative": fn,
            "recall": round(recall, 3),
            "fp_rate": round(fp_rate, 3),
            "precision": round(precision, 3),
            "avg_time_ms": round(total_time / max(1, total)),
        })
    return metrics


__all__ = [
    'get_compiled_binaries', 'run_binmind', 'run_angr',
    'run_ghidra', 'run_qemu', 'compute_metrics',
]
